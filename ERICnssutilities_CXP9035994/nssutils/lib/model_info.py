import config
import log
import persistence
from nssutils.lib.exceptions import ValidationError
import enm_user_2 as enm_user


def validate_models(models):
    """
    Checks if the models given are supported by ENM

    :type: models: list
    :param: models: Name of the node to get the sync status of

    :rtype: boolean
    :returns: whether the NE models given are supported of not

    :raises: ValidationError
    """
    models = [model.lower() for model in models]
    all_supported_models = [model.lower() for model in config.get_prop("supported_ne_models")]
    if not all([model in all_supported_models for model in models]):
        raise ValidationError("One of these models '{0}' is not in the list of supported NetworkElement models '{1}'".format(models, config.get_prop("supported_ne_models")))


def get_supported_model_info(models=None):
    """
    Gets information on all supported network element models

    :type: models: list
    :param: models: Name of the node to get the sync status of

    :rtype: dict
    :returns: all supported NetworkElementModel objects on ENM

    :raises: ValidationError
    """

    all_supported_models = config.get_prop("supported_ne_models")

    # If we have been given models but they are not in the supported list of models, let's raise a runtime error
    if models:
        validate_models(models)

    # If we have not been given models to get info on, let's just search all models
    if not models:
        models_to_check = all_supported_models
    else:
        models_to_check = []
        models = [model.lower() for model in models]
        for supported_model in all_supported_models:
            if supported_model.lower() in models:
                models_to_check.append(supported_model)

    supported_models_dict = {}
    for model in models_to_check:
        supported_ne_types = _get_model_info_from_cli_app(model)
        supported_models_dict[model] = supported_ne_types
        if not supported_ne_types:
            log.logger.debug("No supported NE for model {0}".format(model))

    return supported_models_dict


def _get_model_info_from_cli_app(model):
    """
    Gets a list of all supported Network Elements for this specific model e.g. ERBS etc.

    :type: models: string
    :param: models: Name model we want all supported NE types for (e.g ERBS, RadioNode)

    :rtype: list of NetworkElementModel objects
    :returns: all supported NetworkElements for this model
    """

    model_info_key = "{0}_supported_ne_models".format(model)
    if not persistence.has_key(model_info_key):
        command = config.get_prop("get_supported_model_info_cmd").format(model=model)
        admin_user = enm_user.get_or_create_admin_user()
        response = admin_user.enm_execute(command)
        output = response.get_output()

        supported_nes_for_model = []
        for line in output[1:]:
            data = line.split("\t")
            if len(data) < 7:
                continue
            ne_type, ne_release, product_identity, revision, mim_name, mim_version, model_id = [node_attribute.strip() for node_attribute in data if node_attribute.strip()]
            supported_ne = NetworkElementModel(str(ne_type), str(ne_release), str(product_identity), str(revision), str(mim_name), str(mim_version), str(model_id))
            supported_nes_for_model.append(supported_ne)

        persistence.set(model_info_key, supported_nes_for_model, 60 * 60)

    return persistence.get(model_info_key)


class NetworkElementModel(object):

    def __init__(self, ne_type, ne_release, product_identity, revision, mim_name, mim_version, model_id):
        """
        Constructor for NetworkElementModel object

        :type: ne_type: string
        :param: ne_type: The NE Type of the NetworkElement e.g ERBS
        :type: ne_release: string
        :param: ne_release: The version of ENM on which the NetworkElement was released e.g 15B
        :type: product_identity: string
        :param: product_identity: The product identity of the NetworkElement
        :type rstate: string
        :param rstate: The revision (R-State) of the NetworkElement
        :type: mim_name: string
        :param: mim_name: Them MIM name for the NetworkElement
        :type: mim_version: string
        :param: mim_version: Name IM version for the NetworkElement
        :type: model_id: string
        :param: model_id: Then model identity for the NetworkElement
        :type: revision: string
        :param: revision: Then revision for the NetworkElement (only for SGSN-MME AND RadioNodes)

        :returns: void
        """
        self.ne_type = ne_type
        self.ne_release = ne_release
        self.software_version = product_identity if "-" != product_identity.strip() else None
        self.revision = revision
        self.mim_name = mim_name

        alphabet = config.get_prop("alphabet")
        if ne_type in config.get_prop("cpp_primary_types") and mim_version[0] not in alphabet:
            original_mim = mim_version
            try:
                mim_version = mim_version.split(".")
                mim_version[0] = alphabet[int(mim_version[0]) - 1]
                mim_version = ".".join(mim_version)
            except:
                mim_version = original_mim

        self.mim_version = mim_version
        self.model_id = model_id
