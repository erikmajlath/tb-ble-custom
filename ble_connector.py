#     Copyright 2020. ThingsBoard
#
#     Licensed under the Apache License, Version 2.0 (the "License");
#     you may not use this file except in compliance with the License.
#     You may obtain a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#     Unless required by applicable law or agreed to in writing, software
#     distributed under the License is distributed on an "AS IS" BASIS,
#     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#     See the License for the specific language governing permissions and
#     limitations under the License.

import time
from random import choice
from pprint import pformat
from threading import Thread
from string import ascii_lowercase

from bluepy import __path__ as bluepy_path
from bluepy.btle import DefaultDelegate, Peripheral, Scanner, UUID, capitaliseName, BTLEInternalError
from bluepy.btle import BTLEDisconnectError, BTLEManagementError, BTLEGattError

from thingsboard_gateway.connectors.connector import Connector, log
from thingsboard_gateway.connectors.ble.bytes_ble_uplink_converter import BytesBLEUplinkConverter
from thingsboard_gateway.tb_utility.tb_utility import TBUtility


class BLEConnector(Connector, Thread):
    def __init__(self, gateway, config, connector_type):
        super().__init__()
        self.__connector_type = connector_type
        self.__default_services = list(range(0x1800, 0x183A))
        self.statistics = {'MessagesReceived': 0,
                           'MessagesSent': 0}
        self.__gateway = gateway
        self.__config = config
        self.setName(self.__config.get("name",
                                       'BLE Connector ' + ''.join(choice(ascii_lowercase) for _ in range(5))))

        self._connected = False
        self.__stopped = False
        self.__check_interval_seconds = self.__config['checkIntervalSeconds'] if self.__config.get(
            'checkIntervalSeconds') is not None else 10
        self.__rescan_time = self.__config['rescanIntervalSeconds'] if self.__config.get(
            'rescanIntervalSeconds') is not None else 10
        self.__previous_scan_time = time.time() - self.__rescan_time
        self.__previous_read_time = time.time() - self.__check_interval_seconds
        self.__scanner = Scanner().withDelegate(ScanDelegate(self))
        self.__devices_around = {}
        self.__available_converters = []
        self.__notify_delegators = {}
        self.__fill_interest_devices()
        self.daemon = True

    def run(self):
        # Wrap in try block to catch exceptions
        try:
            while True:
                if time.time() - self.__previous_scan_time >= self.__rescan_time != 0:
                    self.__scan_ble()
                    self.__previous_scan_time = time.time()
                    # Read from new devices right away
                    self.__read_from_new_devices()

                if time.time() - self.__previous_read_time >= self.__check_interval_seconds:
                    self.__read_from_old_devices()
                    self.__previous_read_time = time.time()

                time.sleep(.1)
                if self.__stopped:
                    log.debug('STOPPED')
                    break
        except Exception as e:
            exc_type, exc_value, exc_tb = sys.exc_info()
            log.debug(f"Exception has occured inside BLE custom connector: {e}")
            log.debug(traceback.format_exception(exc_type, exc_value, exc_tb))
            raise e

    def close(self):
        self.__stopped = True
        for device in self.__devices_around:
            try:
                if self.__devices_around[device].get('peripheral') is not None:
                    self.__devices_around[device]['peripheral'].disconnect()
            except Exception as e:
                log.exception(e)
                raise e

    def get_name(self):
        return self.name

    def is_connected(self):
        return self._connected

    def open(self):
        self.__stopped = False
        self.start()

    def device_add(self, device):
        for interested_device in self.__devices_around:
            if device.addr.upper() == interested_device and self.__devices_around[interested_device].get(
                    'scanned_device') is None:
                self.__devices_around[interested_device]['scanned_device'] = device
                self.__devices_around[interested_device]['is_new_device'] = True
            log.debug('Device with address: %s - found.', device.addr.upper())

    def __read_from_old_devices(self):
        log.debug("Reading from non new devices.")
        for name, device in self.__devices_around.items():
            if "is_new_device" in  device and not device["is_new_device"]:
                self.__read_from_device(name)

    def __read_from_new_devices(self):
        log.debug("Reading from new devices.")
        for name, device in self.__devices_around.items():
            if "is_new_device" in  device and device["is_new_device"]:
                self.__read_from_device(name)

    def __read_from_device(self, device):
        log.debug(f"Reading from device: {device}")
        # Fast return if device is not connected
        if (
            self.__devices_around.get(device) is None
            or self.__devices_around[device].get('scanned_device') is None
        ):
            log.debug("Device not ready")
            return False

        try:
            # Connect to device if not already connected
            if self.__devices_around[device].get('peripheral') is None:
                address_type = self.__devices_around[device]['device_config'].get('addrType', "public")
                peripheral = Peripheral(self.__devices_around[device]['scanned_device'], address_type)
                self.__devices_around[device]['peripheral'] = peripheral
            else:
                peripheral = self.__devices_around[device]['peripheral']
            try:
                log.info(peripheral.getState())
            except BTLEInternalError:
                peripheral.connect(self.__devices_around[device]['scanned_device'])
            try:
                services = peripheral.getServices()
            except BTLEDisconnectError:
                self.__check_and_reconnect(device)
                services = peripheral.getServices()

            # Service building
            for service in services:
                if self.__devices_around[device].get('services') is None:
                    log.debug('Building device %s map, it may take a time, please wait...', device)
                    self.__devices_around[device]['services'] = {}
                service_uuid = str(service.uuid).upper()
                if self.__devices_around[device]['services'].get(service_uuid) is None:
                    self.__devices_around[device]['services'][service_uuid] = {}

                    try:
                        characteristics = service.getCharacteristics()
                    except BTLEDisconnectError:
                        self.__check_and_reconnect(device)
                        characteristics = service.getCharacteristics()

                    if self.__config.get('buildDevicesMap', False):
                        for characteristic in characteristics:
                            descriptors = []
                            self.__check_and_reconnect(device)
                            try:
                                descriptors = characteristic.getDescriptors()
                            except BTLEDisconnectError:
                                self.__check_and_reconnect(device)
                                descriptors = characteristic.getDescriptors()
                            except BTLEGattError as e:
                                log.debug(e)
                            except Exception as e:
                                log.debug(f"Exception {e}")
                                log.exception(e)
                            characteristic_uuid = str(characteristic.uuid).upper()
                            if self.__devices_around[device]['services'][service_uuid].get(
                                    characteristic_uuid) is None:
                                self.__check_and_reconnect(device)
                                self.__devices_around[device]['services'][service_uuid][characteristic_uuid] = {'characteristic': characteristic,
                                                                                                                'handle': characteristic.handle,
                                                                                                                'descriptors': {}}
                            for descriptor in descriptors:
                                log.debug(descriptor.handle)
                                log.debug(str(descriptor.uuid))
                                log.debug(str(descriptor))
                                self.__devices_around[device]['services'][service_uuid][
                                    characteristic_uuid]['descriptors'][descriptor.handle] = descriptor
                    else:
                        for characteristic in characteristics:
                            characteristic_uuid = str(characteristic.uuid).upper()
                            self.__devices_around[device]['services'][service_uuid][characteristic_uuid] = {
                                'characteristic': characteristic,
                                'handle': characteristic.handle}

            # New Device section
            if self.__devices_around[device]['is_new_device']:
                log.debug('New device %s - processing.', device)
                self.__devices_around[device]['is_new_device'] = False
                self.__new_device_processing(device)

            # Data gathering
            for interest_char in self.__devices_around[device]['interest_uuid']:
                characteristics_configs_for_processing_by_methods = {}

                for configuration_section in self.__devices_around[device]['interest_uuid'][interest_char]:
                    characteristic_uuid_from_config = configuration_section['section_config'].get("characteristicUUID")
                    if characteristic_uuid_from_config is None:
                        log.error('Characteristic not found in config: %s', pformat(configuration_section))
                        continue
                    method = configuration_section['section_config'].get('method')
                    if method is None:
                        log.error('Method not found in config: %s', pformat(configuration_section))
                        continue
                    characteristics_configs_for_processing_by_methods[method.upper()] = {"method": method, "characteristicUUID": characteristic_uuid_from_config}
                for method in characteristics_configs_for_processing_by_methods:
                    data = self.__service_processing(device, characteristics_configs_for_processing_by_methods[method])
                    for section in self.__devices_around[device]['interest_uuid'][interest_char]:
                        converter = section['converter']
                        converted_data = converter.convert(section, data)
                        self.statistics['MessagesReceived'] = self.statistics['MessagesReceived'] + 1
                        log.debug(data)
                        log.debug(converted_data)
                        self.__gateway.send_to_storage(self.get_name(), converted_data)
                        self.statistics['MessagesSent'] = self.statistics['MessagesSent'] + 1
            
            # If device works in fast disconnect mode, disconnect
            if self.__devices_around[device]['device_config'].get('disconnectOnRead'):
                log.debug("Device runs in the disconnect on read mode. Disconnecting.")
                self.__devices_around[device]["scanned_device"] = None
                peripheral.disconnect()

        except BTLEDisconnectError:
            log.debug('Connection lost. Device %s', device)
        except Exception as e:
            log.exception(e)

    def __new_device_processing(self, device):
        default_services_on_device = [service for service in self.__devices_around[device]['services'].keys() if
                                      int(service.split('-')[0], 16) in self.__default_services]
        log.debug('Default services found on device %s :%s', device, default_services_on_device)
        converter = BytesBLEUplinkConverter(self.__devices_around[device]['device_config'])
        converted_data = None
        for service in default_services_on_device:
            characteristics = [char for char in self.__devices_around[device]['services'][service].keys() if
                               self.__devices_around[device]['services'][service][char][
                                   'characteristic'].supportsRead()]
            for char in characteristics:
                read_config = {'characteristicUUID': char,
                               'method': 'READ',
                               }
                try:
                    self.__check_and_reconnect(device)
                    data = self.__service_processing(device, read_config)
                    attribute = capitaliseName(UUID(char).getCommonName())
                    read_config['key'] = attribute
                    read_config['byteFrom'] = 0
                    read_config['byteTo'] = -1
                    converter_config = [{"type": "attributes",
                                         "clean": False,
                                         "section_config": read_config}]
                    for interest_information in converter_config:
                        try:
                            converted_data = converter.convert(interest_information, data)
                            self.statistics['MessagesReceived'] = self.statistics['MessagesReceived'] + 1
                            log.debug(converted_data)
                        except Exception as e:
                            log.debug(e)
                except Exception as e:
                    log.debug('Cannot process %s', e)
                    continue
        if converted_data is not None:
            # self.__gateway.add_device(converted_data["deviceName"], {"connector": self})
            self.__gateway.send_to_storage(self.get_name(), converted_data)
            self.statistics['MessagesSent'] = self.statistics['MessagesSent'] + 1

    def __check_and_reconnect(self, device):
        # pylint: disable=protected-access
        while self.__devices_around[device]['peripheral']._helper is None:
            log.debug("Connecting to %s...", device)
            self.__devices_around[device]['peripheral'].connect(self.__devices_around[device]['scanned_device'])

    def __service_processing(self, device, characteristic_processing_conf):
        for service in self.__devices_around[device]['services']:
            characteristic_uuid_from_config = characteristic_processing_conf.get('characteristicUUID')
            if self.__devices_around[device]['services'][service].get(characteristic_uuid_from_config.upper()) is None:
                continue
            characteristic = self.__devices_around[device]['services'][service][characteristic_uuid_from_config][
                'characteristic']
            self.__check_and_reconnect(device)
            data = None
            if characteristic_processing_conf.get('method', '_').upper().split()[0] == "READ":
                if characteristic.supportsRead():
                    self.__check_and_reconnect(device)
                    data = characteristic.read()
                    log.debug(data)
                    # If specified, write something to the characteristic, device can respond to this
                    # for example disconnect right away
                    if characteristic_processing_conf.get("writeOnRead", False):
                        log.debug("Writing to characteristic as specified in config.")
                        characteristic.write("E".encode("utf-8"))
                else:
                    log.error('This characteristic doesn\'t support "READ" method.')
            if characteristic_processing_conf.get('method', '_').upper().split()[0] == "NOTIFY":
                self.__check_and_reconnect(device)
                descriptor = characteristic.getDescriptors(forUUID=0x2902)[0]
                handle = descriptor.handle
                if self.__notify_delegators.get(device) is None:
                    self.__notify_delegators[device] = {}
                if self.__notify_delegators[device].get(handle) is None:
                    self.__notify_delegators[device][handle] = {'function': self.__notify_handler,
                                                                'args': (self.__devices_around[device],
                                                                         handle,
                                                                         self.__notify_delegators[device].get(handle)),
                                                                'delegate': None
                                                                }
                    self.__notify_delegators[device][handle]['delegate'] = self.__notify_delegators[device][handle][
                        'function'](*self.__notify_delegators[device][handle]['args'])
                    data = self.__notify_delegators[device][handle]['delegate'].data
                else:
                    self.__notify_delegators[device][handle]['args'] = (self.__devices_around[device],
                                                                        handle,
                                                                        self.__notify_delegators[device][handle]['delegate'])
                    self.__notify_delegators[device][handle]['delegate'] = self.__notify_delegators[device][handle][
                        'function'](*self.__notify_delegators[device][handle]['args'])
                    data = self.__notify_delegators[device][handle]['delegate'].data
            if data is None:
                log.error('Cannot process characteristic: %s with config:\n%s', str(characteristic.uuid).upper(),
                          pformat(characteristic_processing_conf))
            else:
                log.debug('data: %s', data)
            return data

    def __scan_ble(self):
        log.debug("Scanning for devices...")
        try:
            self.__scanner.scan(self.__config.get('scanTimeSeconds', 5),
                                passive=self.__config.get('passiveScanMode', False))
        except BTLEManagementError as e:
            log.error('BLE working only with root user.')
            log.error('Or you can try this command:\nsudo setcap '
                      '\'cap_net_raw,cap_net_admin+eip\' %s'
                      '\n====== Attention! ====== '
                      '\nCommand above - provided access to ble devices to any user.'
                      '\n========================', str(bluepy_path[0] + '/bluepy-helper'))
            self._connected = False
            raise e
        except Exception as e:
            log.exception(e)
            time.sleep(10)

    def __fill_interest_devices(self):
        if self.__config.get('devices') is None:
            log.error('Devices not found in configuration file. BLE Connector stopped.')
            self._connected = False
            return None
        for interest_device in self.__config.get('devices'):
            keys_in_config = ['attributes', 'telemetry']
            if interest_device.get('MACAddress') is not None:
                default_converter = BytesBLEUplinkConverter(interest_device)
                interest_uuid = {}
                for key_type in keys_in_config:
                    for type_section in interest_device.get(key_type):
                        if type_section.get("characteristicUUID") is not None:
                            converter = None
                            if type_section.get('converter') is not None:
                                try:
                                    module = TBUtility.check_and_import(self.__connector_type,
                                                                        type_section['converter'])
                                    if module is not None:
                                        log.debug('Custom converter for device %s - found!',
                                                  interest_device['MACAddress'])
                                        converter = module(interest_device)
                                    else:
                                        log.error(
                                            "\n\nCannot find extension module for device %s .\nPlease check your configuration.\n",
                                            interest_device['MACAddress'])
                                except Exception as e:
                                    log.exception(e)
                            else:
                                converter = default_converter
                            if converter is not None:
                                if interest_uuid.get(type_section["characteristicUUID"].upper()) is None:
                                    interest_uuid[type_section["characteristicUUID"].upper()] = [
                                        {'section_config': type_section,
                                         'type': key_type,
                                         'converter': converter}]
                                else:
                                    interest_uuid[type_section["characteristicUUID"].upper()].append(
                                        {'section_config': type_section,
                                         'type': key_type,
                                         'converter': converter})
                        else:
                            log.error("No characteristicUUID found in configuration section for %s:\n%s\n", key_type,
                                      pformat(type_section))
                if self.__devices_around.get(interest_device['MACAddress'].upper()) is None:
                    self.__devices_around[interest_device['MACAddress'].upper()] = {}
                self.__devices_around[interest_device['MACAddress'].upper()]['device_config'] = interest_device
                self.__devices_around[interest_device['MACAddress'].upper()]['interest_uuid'] = interest_uuid
            else:
                log.error("Device address not found, please check your settings.")


class ScanDelegate(DefaultDelegate):
    def __init__(self, ble_connector):
        DefaultDelegate.__init__(self)
        self.__connector = ble_connector

    def handleDiscovery(self, dev, is_new_device, _):
        if is_new_device:
            self.__connector.device_add(dev)
