# tb-ble-custom
Custom thingsboard gateway BLE connector

## Installation

Create symlink to thingsboard gateway extensions and add settings. https://thingsboard.io/docs/iot-gateway/custom/

## Settings
```json
"devices": [
  {
    ...
    "disconnectOnRead": true,
    "attributes": [
      {
        "writeOnRead": true,
      }
    ]
  }
]
```
