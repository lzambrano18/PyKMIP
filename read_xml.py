import xml.etree.ElementTree as ET
from xmljson import gdata

from kmip.core.enums import AttributeType
from kmip.core.enums import CredentialType
from kmip.core.enums import CryptographicAlgorithm
from kmip.core.enums import CryptographicUsageMask
from kmip.core.enums import ObjectType
from kmip.core.enums import Operation
from kmip.core.enums import ResultStatus
from kmip.core.enums import NameType

from kmip.demos import utils

from kmip.core.factories.attributes import AttributeFactory
from kmip.core.factories.credentials import CredentialFactory

from kmip.core.attributes import Name

from kmip.core.objects import TemplateAttribute
from kmip.core.objects import Attribute

from kmip.services.kmip_client import KMIPProxy

import logging
import sys

from datetime import datetime, timedelta
import time


class ProccessXml:

    def __init__(self, credential, client):
        self.credential = credential
        self.client = client

    def proccess_operation(self, operation, requestPayload):
        if operation['value'] == 'Create':
            if 'ObjectType' in requestPayload:
                object_type = None
                if requestPayload['ObjectType']['value'] == 'SymmetricKey':
                    object_type = ObjectType.SYMMETRIC_KEY
            if 'TemplateAttribute' in requestPayload:
                template_attribute = self.proccess_template_attributes(
                    list(requestPayload['TemplateAttribute']['Attribute']))
            if 'Attribute' in requestPayload:
                for attribute in list(requestPayload['Attribute']):
                    print (attribute['AttributeName'])
                    print (attribute['AttributeValue'])

            result = self.client.create(
                object_type,
                template_attribute,
                self.credential)
            
            # Display operation results
            print('create() result status: {0}'.format(
                result.result_status.value))

            if result.result_status.value == ResultStatus.SUCCESS:
                print('created object type: {0}'.format(
                    result.object_type.value))
                print('created UUID: {0}'.format(result.uuid.value))
                print('created template attribute: {0}'.format(
                    result.template_attribute))
            else:
                print('create() result reason: {0}'.format(
                    result.result_reason.value))
                print('create() result message: {0}'.format(
                    result.result_message.value))

        if operation['value'] == 'Locate':
            if 'Attribute' in requestPayload:
                attributes = self.proccess_attributes(list(requestPayload['Attribute']))

            result = client.locate(attributes=attributes, credential=self.credential)

            # Display operation results
            print('locate() result status: {0}'.format(
                result.result_status.value))

            if result.result_status.value == ResultStatus.SUCCESS:
                print('located UUIDs:')
                for uuid in result.uuids:
                    print('{0}'.format(uuid))
            else:
                print('get() result reason: {0}'.format(
                    result.result_reason.value))
                print('get() result message: {0}'.format(
                    result.result_message.value))


    def proccess_template_attributes(self, attributes):
        template_attributes = []
        attribute_factory = AttributeFactory()
        for attribute in attributes:
            attribute_type = AttributeType(attribute['AttributeName']['value'])
            attribute_value = None

            if attribute_type == AttributeType.X_ID:
                name = Attribute.AttributeName('Name')
                attribute_value = Name.NameValue(attribute['AttributeValue']['value'])
                attribute_type = Name.NameType(NameType.UNINTERPRETED_TEXT_STRING)
                value = Name(name_value=attribute_value, name_type=attribute_type)
                name = Attribute(attribute_name=name, attribute_value=value)
                template_attributes.append(name)
                continue
            if attribute_type == AttributeType.CRYPTOGRAPHIC_ALGORITHM:
                attribute_value = getattr(
                    CryptographicAlgorithm, attribute['AttributeValue']['value'], None)
            if attribute_type == AttributeType.CRYPTOGRAPHIC_LENGTH:
                attribute_value = attribute['AttributeValue']['value']
            if attribute_type == AttributeType.CRYPTOGRAPHIC_USAGE_MASK:
                usage_mask = attribute['AttributeValue']['value'].split(' ')
                for idx, val in enumerate(usage_mask):
                    usage_mask[idx] = getattr(
                        CryptographicUsageMask, val.upper(), None)
                attribute_value = usage_mask

            attribute_obj = attribute_factory.create_attribute(attribute_type, attribute_value)
            template_attributes.append(attribute_obj)
        template_attributes = TemplateAttribute(attributes=template_attributes)
        return template_attributes

    def proccess_attributes(self, attributes):
        list_attributes = []
        attribute_factory = AttributeFactory()
        for attribute in attributes:
            attribute_type = AttributeType(attribute['AttributeName']['value'])
            attribute_value = None
            if attribute_type == AttributeType.OBJECT_TYPE:
                if attribute['AttributeValue']['value'] == 'SymmetricKey':
                    attribute_value = ObjectType.SYMMETRIC_KEY
            if attribute_type == AttributeType.ORIGINAL_CREATION_DATE:
                attribute_value = time.time()
                if attribute['AttributeValue']['value'] == '$NOW-60':
                    attribute_value = attribute_value - 60
                if attribute['AttributeValue']['value'] == '$NOW+60':
                    attribute_value = attribute_value + 60
            attribute_obj = attribute_factory.create_attribute(attribute_type, attribute_value)
            list_attributes.append(attribute_obj)
        return list_attributes

    def proccess_request(self, request):
        batchItems = request['BatchItem']
        if isinstance(batchItems, list):
            for batchItem in batchItems:
                self.proccess_operation(batchItem['Operation'], batchItem['RequestPayload'])
        else:
            self.proccess_operation(batchItems['Operation'], batchItems['RequestPayload'])


if __name__ == '__main__':
    logger = utils.build_console_logger(logging.INFO)

    # Build and parse arguments
    parser = utils.build_cli_parser(Operation.CREATE)
    opts, args = parser.parse_args(sys.argv[1:])

    username = 'leonel'
    password = 'leonel'
    config = opts.config

    credential_factory = CredentialFactory()

    # Build the KMIP server account credentials
    # TODO (peter-hamilton) Move up into KMIPProxy
    if (username is None) and (password is None):
        credential = None
    else:
        credential_type = CredentialType.USERNAME_AND_PASSWORD
        credential_value = {'Username': username,
                            'Password': password}
        credential = credential_factory.create_credential(credential_type, credential_value)

    # Build the client and connect to the server
    client = KMIPProxy(config=config)
    client.open()

    # Read xml and convert to json
    tree = ET.parse('TC-OFFSET-1-13.xml')
    root = tree.getroot()
    json = gdata.data(root)['KMIP']

    # Proccess json
    requestMessages = [json['RequestMessage'][0], json['RequestMessage'][1]]

    proccessXml = ProccessXml(credential, client)
    for resquestMessage in requestMessages: 
        proccessXml.proccess_request(resquestMessage)