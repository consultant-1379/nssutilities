# pylint: disable=R0901
from requests.exceptions import RequestException


class NssUtilsException(Exception):
    pass


class EnmApplicationError(NssUtilsException):
    pass


class ProfileError(NssUtilsException):
    pass


class NetsimError(NssUtilsException):
    pass


class EnvironError(NssUtilsException):
    pass


class ScriptEngineResponseValidationError(EnmApplicationError):
    def __init__(self, msg, response):
        super(ScriptEngineResponseValidationError, self).__init__(msg)
        self.response = response


class EmailerToolResponseError(ScriptEngineResponseValidationError):
    pass


class HistoryMismatch(EnmApplicationError):
    pass


class CmeditCreateSuccessfulValidationError(EnmApplicationError):
    pass


class GetTotalHistoryChangesError(EnmApplicationError):
    pass


class ENMJobStatusError(ScriptEngineResponseValidationError):
    pass


class NoConfigurationManagementHistoryError(ScriptEngineResponseValidationError):
    pass


class ConfigCopyError(EnmApplicationError):
    pass


class CMImportError(EnmApplicationError):
    pass


class RemoveUndoConfigFilesError(EnmApplicationError):
    pass


class ENMJobDetailStatusError(ScriptEngineResponseValidationError):
    pass


class UndoPreparationError(EnmApplicationError):
    pass


class FileDoesNotExist(EnmApplicationError):
    pass


class ConfigActivationError(EnmApplicationError):
    pass


class ConfigCreateError(EnmApplicationError):
    pass


class ConfigDeleteError(EnmApplicationError):
    pass


class DownloadUndoConfigurationFileError(EnmApplicationError):
    pass


class RolesAssignmentError(EnmApplicationError, RequestException):
    pass


class PasswordDisableError(EnmApplicationError, RequestException):
    pass


class ValidationError(NssUtilsException):
    pass


class NotLoadedFmxModuleError(EnmApplicationError):
    pass


class NotActivatedFmxModuleError(EnmApplicationError):
    pass


class FailedNetsimOperation(NetsimError):

    def __init__(self, *args, **kwargs):
        self.nodes = kwargs.pop("nodes", [])
        self.command = kwargs.pop("command", "")
        super(FailedNetsimOperation, self).__init__(*args, **kwargs)


class MoBatchCommandReturnedError(EnvironError):

    def __init__(self, msg, response):
        self.response = response
        super(MoBatchCommandReturnedError, self).__init__(msg)


class ShellCommandReturnedNonZero(EnmApplicationError):

    def __init__(self, msg, response):
        self.response = response
        super(ShellCommandReturnedNonZero, self).__init__(msg)


class NoOuputFromScriptEngineResponseError(EnmApplicationError):
    error_message = "No output from script engine response"

    def __init__(self, msg, response):
        self.response = response
        super(NoOuputFromScriptEngineResponseError, self).__init__(msg)


class TimeOutError(EnmApplicationError):
    pass


class SubscriptionCreationError(EnmApplicationError, RequestException):
    pass


class SubscriptionStatusError(EnmApplicationError):

    def __init__(self, *args, **kwargs):
        self.errors = kwargs.pop('errors', None)
        super(SubscriptionStatusError, self).__init__(*args, **kwargs)


class JobExecutionError(EnmApplicationError):

    def __init__(self, msg, response):
        self.response = response
        super(JobExecutionError, self).__init__(msg)


class JobValidationError(EnmApplicationError):

    def __init__(self, msg, response):
        self.response = response
        super(JobValidationError, self).__init__(msg)


class AlarmRouteExistsError(EnmApplicationError):
    pass


class ProfileAlreadyRunning(ProfileError):
    def __init__(self, msg, pid, host="localhost"):
        self.host = host
        self.pid = pid
        super(ProfileAlreadyRunning, self).__init__(msg)


class NotSupportedException(ProfileError):
    pass


class SessionNotEstablishedException(NssUtilsException):
    pass


class NetworkTopologyError(EnmApplicationError):
    pass


class NoNodesAvailable(EnvironError):
    pass


class NotAllNodeTypesAvailable(EnvironError):
    pass


class FileNotUpdatedError(ProfileError):
    pass


class NodeExchangeError(EnvironError):
    pass


class RpmMisMatch(Exception):
    pass


class RemoveProfileFromNodeError(ProfileError):
    pass


class AddProfileToNodeError(ProfileError):
    pass


class DependencyException(RuntimeError):
    error = ""
    host = ""
    command = ""
    message = ""

    def __init__(self, host, command, error):
        self.error = error
        self.host = host
        self.command = command
        self.message = "ERROR\n    Host: {hostname}\n    Command: {command}\n    Error: {error}".format(hostname=self.host, command=self.command, error=self.error)
        super(DependencyException, self).__init__(self.message)


class InvalidSoftwarePackage(DependencyException):

    def __init__(self, host, command, error):
        super(InvalidSoftwarePackage, self).__init__(host, command, error)


class NetworkElementMigrationException(RuntimeError):
    host = ""
    error = ""
    message = ""

    def __init__(self, host, error):
        self.error = error
        self.host = host
        self.message = "ERROR\n    Host: {hostname}\n    Error: {error}".format(hostname=self.host, error=self.error)
        super(NetworkElementMigrationException, self).__init__(self.message)


class SyncException(NetworkElementMigrationException):

    def __init__(self, host, error):
        super(SyncException, self).__init__(host, error)


class EnmUserRoleMissingException(NetworkElementMigrationException):

    def __init__(self, host, error):
        super(EnmUserRoleMissingException, self).__init__(host, error)


class NoRemainingNetworkElementsException(NetworkElementMigrationException):

    def __init__(self, host, error):
        super(NoRemainingNetworkElementsException, self).__init__(host, error)


class InvalidSearchError(Exception):
    pass
