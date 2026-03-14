const { parentPort, workerData } = require('worker_threads');
const winston = require('winston');
const { loggerTypes } = require('../logging/logger');
const { chunk } = require('lodash');
const parseEmail = require('./utils/parseEmail');
const isRoleAccount = require('./utils/isRoleAccount');
const isFreeDomain = require('./utils/isFreeDomain');
const disposableDomainsList = require('../../data/lists/disposableDomainsList');
const getMXRecords = require('./utils/getMXRecords');
const SMTPVerificationSC = require('./utils/smtpVerificationSC');
const calculateReachable = require('./utils/calculateReachable');
const checkGravatar = require('./utils/checkGravatar');
const promiseAwait = require('../utils/promiseAwait');
const stateVariables = require('../../data/stateVariables');
const emailSplit = require('../utils/emailSplit');
const microsoftLoginVerification = require('./utils/microsoftLoginVerification');
const microsoftEmailDomains = require('../../data/lists/microsoftEmailDomains');
const yahooEmailDomains = require('../../data/lists/yahooEmailDomains');
const MXOrganizationClassifier = require('./utils/mxOrganizationClassifier');
const MXProcessingProfiles = require('./utils/mxProcessingProfiles');

const _mxCache = new Map();
const MX_CACHE_TTL_MS = 5 * 60 * 1000;

async function getMXRecordsCached(email) {
	const domain = email.includes('@') ? email.split('@')[1].toLowerCase() : email.toLowerCase();
	const cached = _mxCache.get(domain);
	if (cached && cached.expiresAt > Date.now()) return cached.records;
	const records = await getMXRecords(email);
	_mxCache.set(domain, { records, expiresAt: Date.now() + MX_CACHE_TTL_MS });
	if (_mxCache.size > 2000) {
		const now = Date.now();
		for (const [k, v] of _mxCache) {
			if (v.expiresAt <= now) _mxCache.delete(k);
		}
	}
	return records;
}
/**
 * This class is used to create a verifier instance
 */
class VerifierInstance {
	/** @private @type {Omit<RequestObj, "response_url"> | undefined} - current verifier request obj */
	curr_request;

	/** @private logger for winston */
	logger =
		workerData?.index === 0
			? winston.loggers.get(loggerTypes.verifier0)
			: workerData?.index === 1
				? winston.loggers.get(loggerTypes.verifier1)
				: workerData?.index === 2
					? winston.loggers.get(loggerTypes.verifier2)
					: workerData?.index === 3
						? winston.loggers.get(loggerTypes.verifier3)
						: winston.loggers.get(loggerTypes.verifier);
	/** @private {import("worker_threads").MessagePort | null} Message port to connect to parent */
	parentPort;

	/** @private @type {number} - max recipients per email */
	_max_rcpt = 50;
	/** @private @type {string[]} - keywords to flag for single recipient */
	_single_rcpt_keywords = ['google.com', '.protection.outlook.com', 'icloud.com']; // make sure that they are in lower case
	/** @private @type {Set<string>} - all the domains to be counted as microsoft domains */
	_microsoft_email_domains = new Set(microsoftEmailDomains);
	/** @private @type {Set<string>} - all the domains to be counted as yahoo domains */
	_yahoo_email_domains = new Set(yahooEmailDomains);
	/** @private MX Organization Classifier for rate limiting */
	_mxClassifier = new MXOrganizationClassifier();
	/** @private MX Processing Profiles */
	_mxProcessingProfiles = new MXProcessingProfiles();

	/**
	 * Helper method to safely get error message
	 * @param {unknown} error - The error object
	 * @returns {string}
	 */
	getErrorMessage(error) {
		return error instanceof Error ? error.message : String(error);
	}

	/**
	 * @param {import("worker_threads").MessagePort | null} parentPort
	 */
	constructor(parentPort) {
		this.parentPort = parentPort;
	}

	/** add a new request
	 * @param {Omit<RequestObj, "response_url">} request
	 */
	async add(request) {
		let success = false;
		try {
			// check if there is already a request running
			if (this.curr_request) {
				throw new Error(
					`A request is already running under the verifier worker! Request ID -> ${this.curr_request?.request_id}`
				);
			}

			// save the request as the current request
			this.curr_request = {
				request_id: request?.request_id,
				emails: request?.emails,
			};

			// start processing the current request
			this.process();
		} catch (error) {
			this.logger.error(`run() error -> ${error?.toString()}`);
		} finally {
			return success;
		}
	}

	/**
	 * start processing the current request
	 * @protected
	 */
	async process() {
		try {
			if (!this.curr_request) return;

			// perform quick verification - non SMTP verification
			const quickVerificationResult = await this.quickVerification(this.curr_request?.emails);

			// perform SMTP verfication for the ones that have MX records
			const { finalResult, greylistedEmails, blacklistedEmails, recheckRequired } = await this.smtpVerification(
				quickVerificationResult
			);

			// clear the current request
			const request_id = this.curr_request.request_id;
			this.curr_request = undefined;

			// inform the parent worker that the job has been done
			if (this.parentPort) {
				this.parentPort.postMessage({
					type: 'complete',
					request_id: request_id,
					result: finalResult, // -> the controller will be responsible behind sending the results to the user
					greylisted_emails: greylistedEmails,
					blacklisted_emails: blacklistedEmails,
					recheck_required: recheckRequired,
				});
				this.logger.debug(
					`Informed the parent port for request -> ${request_id} result size ${finalResult.size}`
				);
			}
		} catch (error) {
			this.logger.error(`process() error -> ${error?.toString()}`);
		}
	}

	/** this function will perform quick Verification on the request emails
	 * @protected
	 * @param {string[]} emails
	 */
	async quickVerification(emails) {
		const concurrent_request = 20,
			/** @type {Map<string, QuickVerificationResult>} - Map of emails to quick verification results */
			allResults = new Map();
		try {
			// break the list of emails into chunks and process concurrently
			const chunks = chunk(emails, concurrent_request);

			// The default response for quick verification
			const defaultQuickRes = {
				email: '',
				syntax: {
					username: '',
					domain: '',
					valid: false,
				},
				role_account: false,
				free: false,
				disposable: false,
				mx: [],
				has_mx_records: false,
			};

			// run quick verification on the groups
			for (const group of chunks) {
				await Promise.allSettled(
					group.map(async email => {
						/** @type {QuickVerificationResult} */
						const quickCheckResult = JSON.parse(JSON.stringify(defaultQuickRes));
						quickCheckResult.email = email; // adding the email to the result obj

						// add the default quick check result to the allResults Map
						allResults.set(email, quickCheckResult);

						// making Verification checks
						// -> parse email
						const parseResult = parseEmail(email);
						quickCheckResult.syntax = parseResult;

						// -> check if they are role accounts + free domains + disposable
						quickCheckResult.role_account = isRoleAccount(parseResult.username);
						quickCheckResult.free = isFreeDomain(parseResult.domain);
						quickCheckResult.disposable = disposableDomainsList.has(parseResult.domain);

						// make mx check
						if (!quickCheckResult.disposable) {
							// -> get the mx records
							const mx_records = await getMXRecordsCached(email);
							quickCheckResult.mx = mx_records.map(res => ({
								Host: res.exchange,
								Pref: res.priority,
							}));
							quickCheckResult.has_mx_records = quickCheckResult.mx.length > 0;
						}

						// set the new quick verification result to the allResult Map
						allResults.set(email, quickCheckResult);

						return quickCheckResult;
					})
				);
			}
		} catch (error) {
			this.logger.error(`quickVerification() error -> ${error?.toString()}`);
		} finally {
			return allResults;
		}
	}

	/** this function will perform SMTP verification on the request emails
	 * @protected
	 * @param {Map<string, QuickVerificationResult>} quickVerificationResult
	 */
	async smtpVerification(quickVerificationResult) {
		/** @type {Map<string, VerificationObj>} */
		const finalResult = new Map();
		/** @type {string[]} - Greylisted emails */
		const greylistedEmails = [];
		/** @type {string[]} = blacklisted emails */
		const blacklistedEmails = [];
		/** @type {string[]} = emails that requires recheck */
		const recheckRequired = [];

		// add dummy data from the quick verifier results
		const emails = quickVerificationResult.keys();
		for (const email of emails) {
			const quickRes = quickVerificationResult.get(email);

			if (quickRes)
				finalResult.set(email, {
					...quickRes,
					smtp: {
						host_exists: false,
						full_inbox: false,
						catch_all: false,
						deliverable: false,
						disabled: false,
					},
					error: false,
					error_msg: '',
					reachable: 'unknown',
					gravatar: '',
					suggestion: '',
				});
		}

		try {
			// run login verification for outlook, live, and hotmail emails
			const emails = Array.from(quickVerificationResult.keys()),
				microsoftEmails = emails.filter(email => {
					const { domain } = emailSplit(email?.toLowerCase());

					if (this._microsoft_email_domains.has(domain?.toLowerCase())) return true;
					else return false;
				}),
				yahooEmails = emails.filter(email => {
					const { domain } = emailSplit(email?.toLowerCase());

					if (this._yahoo_email_domains.has(domain?.toLowerCase())) return true;
					return false;
				});
			if (microsoftEmails.length > 0) {
				// perform login verification on microsoft emails
				const loginResults = await this.msLoginVerification(microsoftEmails);

				// update the results
				for (const msEmail of microsoftEmails) {
					const loginRes = loginResults.get(msEmail);
					const quickRes = quickVerificationResult.get(msEmail);

					if (quickRes && loginRes)
						finalResult.set(msEmail, {
							...quickRes,
							...loginRes,
						});
				}
			}

			// run alternate verification methods for yahoo emails
			if (yahooEmails.length > 0) {
				// perform alternate verification
				const yahooResults = await this.yahooVerification(yahooEmails);

				// update the results
				for (const yahooEmail of yahooEmails) {
					const yahooRes = yahooResults.get(yahooEmail);
					const quickRes = quickVerificationResult.get(yahooEmail);

					if (quickRes && yahooRes)
						finalResult.set(yahooEmail, {
							...quickRes,
							...yahooRes,
						});
				}
			}

			// sort the emails according to MX organization - group by organization for rate limiting + skip MS & Yahoo emails
			const groups = this.groupByMxOrganization(Array.from(quickVerificationResult.values()), [
				...microsoftEmails,
				...yahooEmails,
			]);

			// Get the emails that don't have mx records (they need to be checked again just to be sure)
			const requires_recheck = this.noMxHost(Array.from(quickVerificationResult.values()), []);
			recheckRequired.push(...requires_recheck); // add all the values

			// run these organization group verifications with appropriate rate limiting
			const processOrgGroup = async (orgGroup) => {
				try {
					// Validate organization group
					if (!orgGroup || !orgGroup.emails || !Array.isArray(orgGroup.emails)) {
						this.logger.warn('Invalid organization group:', orgGroup);
						return;
					}

					// Get processing configuration for this organization
					let processingConfig;
					try {
						processingConfig = this._mxProcessingProfiles.getProcessingConfig(orgGroup.processingProfile);
					} catch (error) {
						this.logger.error(
							`Error getting processing config for ${orgGroup.organization}:`,
							this.getErrorMessage(error)
						);
						processingConfig = this._mxProcessingProfiles.getDefaultProcessingConfig();
					}

					// Extract emails and MX records from the organization group
					const emails = orgGroup.emails
						.map(obj => obj?.email || '')
						.filter(email => email && typeof email === 'string' && email.trim());

					if (emails.length === 0) {
						this.logger.warn(`No valid emails found in organization group: ${orgGroup.organization}`);
						return;
					}

					const mx_records = orgGroup.emails[0]?.mx || [];

					if (!mx_records || mx_records.length === 0) {
						this.logger.warn(`No MX records found for organization: ${orgGroup.organization}`);
						return; // skips the one with no mx record
					}

					this.logger.debug(
						`Processing ${emails.length} emails for organization: ${orgGroup.organization} using profile: ${orgGroup.processingProfile}`
					);

					// Apply organization-specific rate limiting and batching
					let emailSubGroup;
					try {
						emailSubGroup = this.createSubGroupsWithRateLimit(emails, mx_records, processingConfig);
					} catch (error) {
						this.logger.error(
							`Error creating sub groups for ${orgGroup.organization}:`,
							this.getErrorMessage(error)
						);
						return;
					}

					// -> email sub group is a group of emails of length as per standards
					if (!emailSubGroup || !Array.isArray(emailSubGroup)) {
						this.logger.warn(`Invalid email sub group for organization: ${orgGroup.organization}`);
						return;
					}

					for (let i = 0; i < emailSubGroup.length; i++) {
						try {
							const emailsInGroup = emailSubGroup[i];

							if (!emailsInGroup || !Array.isArray(emailsInGroup) || emailsInGroup.length === 0) {
								this.logger.warn(
									`Invalid or empty email group at index ${i} for organization: ${orgGroup.organization}`
								);
								continue;
							}

							/** @type {Map<string, any>} */
							let smtpResult;
							try {
								// Use real SMTP verification
								const smtpVerification = new SMTPVerificationSC(workerData?.index);
								smtpResult = await smtpVerification.check(emailsInGroup, mx_records);
							} catch (smtpError) {
								this.logger.error(
									`SMTP verification failed for organization ${orgGroup.organization}, batch ${i}:`,
									this.getErrorMessage(smtpError)
								);

								// Create default failed results for this batch
								smtpResult = new Map();
								emailsInGroup.forEach(email => {
									smtpResult.set(email, {
										host_exists: false,
										full_inbox: false,
										catch_all: false,
										deliverable: false,
										disabled: false,
										error: true,
										error_msg: `SMTP verification failed: ${this.getErrorMessage(smtpError)}`,
									});
								});
							}

							// Apply rate limiting delay between batches (except for the last batch)
							try {
								if (i < emailSubGroup.length - 1 && processingConfig.delayBetweenBatches > 0) {
									await promiseAwait(processingConfig.delayBetweenBatches / 1000);
								}
							} catch (delayError) {
								this.logger.warn(`Error in rate limiting delay:`, this.getErrorMessage(delayError));
								// Continue without delay
							}

							// combine the SMTP results with the quick verification results
							try {
								const keys = smtpResult.keys();
								for (const key of keys) {
									try {
										const resultObj = smtpResult.get(key);

										if (resultObj) {
											const smtp = {
												host_exists: resultObj.host_exists,
												full_inbox: resultObj.full_inbox,
												catch_all: resultObj.catch_all,
												deliverable: resultObj.deliverable,
												disabled: resultObj.disabled,
											};

											// if greylisted add to the greylistedEmails list
											if (!!resultObj?.greylisted) greylistedEmails.push(key);
											if (!!resultObj?.disabled) blacklistedEmails.push(key);
											if (!!resultObj?.requires_recheck) recheckRequired.push(key);

											// calculate reachable
											const reachable = calculateReachable(smtp);

											// get gravatar
											let gravatar = ''; // filled in async
											checkGravatar(key).then(g => {
												const ex = finalResult.get(key);
												if (ex) finalResult.set(key, { ...ex, gravatar: g });
											}).catch(() => { });

											const errObj = {
												error: resultObj?.error,
												error_msg: resultObj?.errorMsg?.message,
											};

											const quickRes = quickVerificationResult.get(key);

											if (quickRes) {
												finalResult.set(key, {
													smtp,
													...errObj,
													...quickRes,
													reachable,
													gravatar,
													suggestion: '', // leaving this one for now
												});
											}
										}
									} catch (keyError) {
										this.logger.error(
											`Error processing result for ${key}:`,
											this.getErrorMessage(keyError)
										);
									}
								}
							} catch (combineError) {
								this.logger.error(`Error combining SMTP results:`, this.getErrorMessage(combineError));
							}
						} catch (batchError) {
							this.logger.error(
								`Error processing SMTP verification batch ${i}:`,
								this.getErrorMessage(batchError)
							);
						}
					}
				} catch (orgError) {
					this.logger.error(`Error processing organization group:`, this.getErrorMessage(orgError));
				}

			}
			await Promise.all(groups.map(orgGroup => processOrgGroup(orgGroup)));
		} catch (error) {
			this.logger.error(`smtpVerification() error -> ${error?.toString()}`);
		} finally {
			return { finalResult, greylistedEmails, blacklistedEmails, recheckRequired };
		}
	}

	/** Login verification for outlook, live and hotmail emails
	 * @param {string[]} emails
	 */
	async msLoginVerification(emails) {
		/** @type {Map<string, Omit<VerificationObj, "disposable" | "free" | "has_mx_records" | "mx" | "role_account" | "syntax">>} */
		let finalResult = new Map();

		// set dummy data
		for (const email of emails)
			finalResult.set(email, {
				email,
				smtp: {
					host_exists: false,
					full_inbox: false,
					catch_all: false,
					deliverable: false,
					disabled: false,
				},
				error: false,
				error_msg: '',
				reachable: 'unknown',
				gravatar: '',
				suggestion: '',
			});
		try {
			for (const email of emails) {
				const { valid } = await microsoftLoginVerification(email);

				if (!valid) continue;

				const smtp = {
					host_exists: true,
					full_inbox: false,
					catch_all: false,
					deliverable: valid,
					disabled: false,
				};

				// calculate reachable
				const reachable = calculateReachable(smtp);

				// get gravatar
				const gravatar = await checkGravatar(email);

				const errObj = {
					error: false,
					error_msg: '',
				};

				finalResult.set(email, {
					email,
					smtp,
					...errObj,
					reachable,
					gravatar,
					suggestion: '', // leaving this one for now
				});
			}
		} catch (error) {
			this.logger.error(`loginVerification() error -> ${error?.toString()}`);
		} finally {
			return finalResult;
		}
	}

	/** Yahoo verification
	 * @param {string[]} emails
	 */
	async yahooVerification(emails) {
		/** @type {Map<string, Omit<VerificationObj, "disposable" | "free" | "has_mx_records" | "mx" | "role_account" | "syntax">>} */
		let finalResult = new Map();

		// set dummy data
		for (const email of emails)
			finalResult.set(email, {
				email,
				smtp: {
					host_exists: true, // hosts will exist for yahoo emails
					full_inbox: false,
					catch_all: true, // yahoo emails are always catch-all
					deliverable: false,
					disabled: false,
				},
				error: false,
				error_msg: '',
				reachable: 'unknown',
				gravatar: '',
				suggestion: '',
			});
		try {
			// perform nodemailer verification by waiting for bounce emails (might take too long)
			// -> code here <-
			// OR
			// use 3rd party API & database
			// -> code here <-
		} catch (error) {
			this.logger.error(`yahooVerification() error -> ${error?.toString()}`);
		} finally {
			return finalResult;
		}
	}

	/**
	 * Function to group quick verification results by MX organization (for rate limiting by organization)
	 * @param {QuickVerificationResult[]} quickVerificationResults
	 * @param {string[]} skipEmails - emails to skip in the grouping process (MS & Yahoo already handled)
	 * @returns {Array<{organization: string, processingProfile: string, emails: QuickVerificationResult[]}>}
	 * @protected
	 */
	groupByMxOrganization(quickVerificationResults, skipEmails = []) {
		try {
			// Input validation
			if (!quickVerificationResults || !Array.isArray(quickVerificationResults)) {
				this.logger.warn('Invalid quick verification results provided to groupByMxOrganization');
				return [];
			}

			if (!skipEmails || !Array.isArray(skipEmails)) {
				this.logger.warn('Invalid skip emails provided, using empty array');
				skipEmails = [];
			}

			const organizationGroups = new Map();
			const skipEmailsSet = new Set(skipEmails);

			quickVerificationResults.forEach((result, index) => {
				try {
					// Validate result object
					if (!result || typeof result !== 'object' || !result.email) {
						this.logger.warn(`Invalid result at index ${index}:`, result);
						return;
					}

					if (skipEmailsSet.has(result.email)) {
						return; // Skip this email
					}

					if (!result.mx || !Array.isArray(result.mx) || result.mx.length === 0) {
						this.logger.debug(`No MX records for email: ${result.email}`);
						return;
					}

					// Get the primary MX record (lowest priority)
					let primaryMX;
					try {
						primaryMX = result.mx.reduce((prev, current) => {
							if (!prev || !current) return prev || current;
							if (typeof prev.Pref !== 'number' || typeof current.Pref !== 'number') {
								this.logger.warn('Invalid MX preference values:', { prev, current });
								return prev;
							}
							return prev.Pref < current.Pref ? prev : current;
						});
					} catch (reduceError) {
						this.logger.warn(
							`Error finding primary MX for ${result.email}:`,
							this.getErrorMessage(reduceError)
						);
						primaryMX = result.mx[0]; // Fallback to first MX record
					}

					if (!primaryMX || !primaryMX.Host) {
						this.logger.warn(`Invalid primary MX record for ${result.email}:`, primaryMX);
						return;
					}

					// Classify the MX domain to get organization
					let classification;
					try {
						classification = this._mxClassifier.classifyMXDomain(primaryMX.Host);
					} catch (classifyError) {
						this.logger.error(
							`Error classifying MX domain ${primaryMX.Host}:`,
							this.getErrorMessage(classifyError)
						);
						// Use default classification
						classification = {
							organization: 'unknown_error',
							processingProfile: 'unknown_mx_ultra_conservative',
							confidence: 'low',
							source: 'error_fallback',
						};
					}

					const organization = classification.organization || 'unknown_default';

					// Group by organization
					if (!organizationGroups.has(organization)) {
						organizationGroups.set(organization, {
							organization: organization,
							processingProfile: classification.processingProfile || 'unknown_mx_ultra_conservative',
							confidence: classification.confidence || 'low',
							source: classification.source || 'fallback',
							emails: [],
						});
					}

					// Add the result to the organization group
					organizationGroups.get(organization).emails.push(result);
				} catch (resultError) {
					this.logger.error(`Error processing result at index ${index}:`, this.getErrorMessage(resultError));
					// Continue with next result
				}
			});

			// Convert map to array and sort by organization for consistent processing
			try {
				const groups = Array.from(organizationGroups.values());
				return groups.sort((a, b) => {
					try {
						return a.organization.localeCompare(b.organization);
					} catch (sortError) {
						this.logger.warn('Error sorting organizations:', this.getErrorMessage(sortError));
						return 0;
					}
				});
			} catch (convertError) {
				this.logger.error('Error converting organization groups to array:', this.getErrorMessage(convertError));
				return [];
			}
		} catch (error) {
			this.logger.error('Critical error in groupByMxOrganization:', this.getErrorMessage(error));
			return [];
		}
	}

	/** Function to group by MX Hosts (legacy method - kept for backward compatibility)
	 * @param {QuickVerificationResult[]} quickVerificationResults
	 * @param {string[]} msEmails - emails to skip in the grouping process
	 * @returns {QuickVerificationResult[][]}
	 * @protected
	 */
	groupByMxHosts(quickVerificationResults, msEmails = []) {
		const groups = new Map();
		const msEmailsSet = new Set(msEmails);

		quickVerificationResults.forEach(result => {
			if (!msEmailsSet.has(result.email)) {
				// Extract hosts and sort them to normalize order
				const key = result.mx
					.map(mx => mx.Host)
					.sort()
					.join(',');

				// make sure that we leave out the ones for which MX host was to found
				if (key) {
					// Check if this key already exists in the map
					if (!groups.has(key)) {
						groups.set(key, []);
					}

					// Add the record to the correct group
					groups.get(key).push(result);
				}
			}
		});

		// Converting the map to an array of groups for easier usage
		return Array.from(groups.values());
	}

	/** Function to return the entires with no mx Hosts
	 * @param {QuickVerificationResult[]} quickVerificationResults
	 * @param {string[]} msEmails - emails to skip in the grouping process
	 * @returns {string[]}
	 */
	noMxHost(quickVerificationResults, msEmails) {
		const msEmailsSet = new Set(msEmails);
		const emailsWithNoMX = new Set();

		for (const res of quickVerificationResults) {
			if (!res.has_mx_records && !msEmailsSet.has(res.email)) {
				emailsWithNoMX.add(res.email);
			}
		}

		return Array.from(emailsWithNoMX);
	}

	/**
	 * Function to create sub groups with organization-specific rate limiting
	 * @param {string[]} emails
	 * @param {{Host: string, Pref: number}[]} mx_records
	 * @param {Object} processingConfig - Organization-specific processing configuration
	 * @returns {string[][]}
	 */
	createSubGroupsWithRateLimit(emails, mx_records, processingConfig) {
		try {
			// Input validation
			if (!emails || !Array.isArray(emails) || emails.length === 0) {
				this.logger.warn('Invalid or empty emails array provided to createSubGroupsWithRateLimit');
				return [];
			}

			if (!mx_records || !Array.isArray(mx_records) || mx_records.length === 0) {
				this.logger.warn('Invalid or empty MX records provided to createSubGroupsWithRateLimit');
				return [emails]; // Return emails as single group if no MX records
			}

			if (!processingConfig || typeof processingConfig !== 'object') {
				this.logger.warn('Invalid processing config provided, using defaults');
				processingConfig = { batchSize: 10 };
			}

			// Use organization-specific batch size instead of default
			let batchSize;
			try {
				batchSize = /** @type {any} */ (processingConfig).batchSize || 10;
				if (typeof batchSize !== 'number' || batchSize < 1) {
					this.logger.warn('Invalid batch size, using default of 10');
					batchSize = 10;
				}
			} catch (error) {
				this.logger.warn('Error getting batch size:', this.getErrorMessage(error));
				batchSize = 10;
			}

			// Check if this MX provider requires single recipient mode
			let mx_flagged = false;
			try {
				const mx_records_str = mx_records
					.map(record => {
						try {
							return record && record.Host ? record.Host : '';
						} catch (error) {
							this.logger.warn('Error processing MX record:', this.getErrorMessage(error));
							return '';
						}
					})
					.join(' | ')
					.toLowerCase();

				for (const keyword of this._single_rcpt_keywords) {
					try {
						if (mx_records_str.indexOf(keyword) !== -1) {
							mx_flagged = true;
							break;
						}
					} catch (error) {
						this.logger.warn(`Error checking keyword ${keyword}:`, this.getErrorMessage(error));
					}
				}
			} catch (error) {
				this.logger.warn('Error checking MX flagging:', this.getErrorMessage(error));
				mx_flagged = false;
			}

			if (mx_flagged) {
				try {
					// For providers that require single recipient (like Google), group by domain
					const domainMap = new Map();

					emails.forEach((email, index) => {
						try {
							if (!email || typeof email !== 'string') {
								this.logger.warn(`Invalid email at index ${index}:`, email);
								return;
							}

							const { domain } = emailSplit(email.toLowerCase());
							if (!domain) {
								this.logger.warn(`Could not extract domain from email: ${email}`);
								return;
							}

							if (!domainMap.has(domain)) {
								domainMap.set(domain, []);
							}
							domainMap.get(domain).push(email);
						} catch (error) {
							this.logger.warn(`Error processing email ${email}:`, this.getErrorMessage(error));
						}
					});

					// Create batches respecting organization limits
					const result = [];
					for (const domainEmails of domainMap.values()) {
						try {
							for (let i = 0; i < domainEmails.length; i += batchSize) {
								const batch = domainEmails.slice(i, i + batchSize);
								if (batch.length > 0) {
									result.push(batch);
								}
							}
						} catch (error) {
							this.logger.warn('Error creating domain batches:', this.getErrorMessage(error));
						}
					}
					return result;
				} catch (error) {
					this.logger.error('Error in domain-based grouping:', this.getErrorMessage(error));
					// Fallback to simple batching
				}
			}

			// For other providers, use simple batching based on organization limits
			try {
				const result = [];
				for (let i = 0; i < emails.length; i += batchSize) {
					const batch = emails.slice(i, i + batchSize);
					if (batch.length > 0) {
						result.push(batch);
					}
				}
				return result;
			} catch (error) {
				this.logger.error('Error in simple batching:', this.getErrorMessage(error));
				// Ultimate fallback: return all emails as single batch
				return [emails];
			}
		} catch (error) {
			this.logger.error('Critical error in createSubGroupsWithRateLimit:', this.getErrorMessage(error));
			// Ultimate fallback: return emails as single group
			return emails && Array.isArray(emails) && emails.length > 0 ? [emails] : [];
		}
	}

	/**
	 * Function to create sub groups based on group length & gmail accounts (legacy method)
	 * @param {string[]} emails
	 * @param {{Host: string, Pref: number}[]} mx_records
	 */
	createSubGroups(emails, mx_records) {
		let mx_flagged = false; // mx_flagged determines if the SMTP server supports multiple domain recipients (e.g. in case of google they don't)

		const mx_records_str = mx_records.reduce((f, c) => f + c.Host + ' | ', '')?.toLowerCase(); // transform to lowercase
		for (const keyword of this._single_rcpt_keywords) {
			if (mx_records_str.indexOf(keyword) !== -1) {
				mx_flagged = true;
				break;
			}
		}

		// if mx_flagged then return each email one by one, else group based on max rcpts allowed
		if (mx_flagged) {
			// group based on domains
			/**
			 * Domain map for emails
			 * @type {Map<string, string[]>}
			 */
			const domainMap = new Map();

			for (const email of emails) {
				const { domain } = emailSplit(email);
				if (!domainMap.get(domain)) domainMap.set(domain, [email]);
				else {
					const emailArr = domainMap.get(domain);
					if (emailArr) domainMap.set(domain, [...emailArr, email]);
				}
			}

			return Array.from(domainMap.values());
		} else {
			const emailChunks = chunk(emails, this._max_rcpt);
			return emailChunks;
		}
	}
}

const verifierInstance = new VerifierInstance(parentPort);

// Listen for messages from the parent thread
if (parentPort) {
	parentPort.on('message', async msg => {
		// get the type of message
		const type = msg?.type;
		switch (type) {
			case 'request': {
				delete msg.type;

				// run the request
				await verifierInstance.add(msg);

				break;
			}
			default: {
			}
		}
	});

	// keep on pinging the parent process
	(async () => {
		while (true) {
			parentPort.postMessage({ type: 'ping' });
			await promiseAwait(stateVariables.ping_freq);
		}
	})();
}

process.on('unhandledRejection', (reason, promise) => {
	console.error('Unhandled Rejection at:', promise, 'reason:', reason);
	// Application specific logging, throwing an error, or other logic here
});

process.on('uncaughtException', err => {
	console.error('Uncaught Exception thrown:', err);
	// Application specific logging, throwing an error, or other logic here
	process.exit(1); // optional: exit the process to avoid undefined state
});

module.exports = VerifierInstance;
