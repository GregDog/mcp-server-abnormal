package tools

import "errors"

const errConfirmationRequired = "confirmation required"

var (
	errIDRequired                = errors.New("id is required")
	errMessageIDRequired         = errors.New("message_id is required")
	errActivityIDRequired        = errors.New("activity_log_id is required")
	errActionIDRequired          = errors.New("action_id is required")
	errSenderConflict            = errors.New("sender and sender_domain cannot both be set")
	errSinceAfterUntil           = errors.New("since must be before until")
	errResponseDisabled          = errors.New("response tools are disabled; set ABNORMAL_ALLOW_RESPONSE=true")
	errRemediationActionRequired = errors.New("action is required")
	errRemediationReasonRequired = errors.New("remediation_reason is required")
	errMessagesRequired          = errors.New("messages is required when remediate_all is false")
	errSearchFiltersRequired     = errors.New("search filters are required when remediate_all is true")
	errTargetFolderRequired      = errors.New("target_folder is required when action is move_to_inbox")
	errThreatActionRequired      = errors.New("action must be remediate or unremediate")
	errEmailRequired             = errors.New("email is required")
	errVendorDomainRequired      = errors.New("vendor_domain is required")
	errCaseActionRequired        = errors.New("action is required")
)
