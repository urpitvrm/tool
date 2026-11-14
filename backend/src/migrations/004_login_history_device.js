// Device family (browser + OS) per sign-in, used to detect sign-ins from unrecognized devices.
// Separate from 003 because 003 had already been applied when this column was introduced.
export default {
  version: '004',
  description: 'Device information on login history',
  up: `
    ALTER TABLE login_history ADD COLUMN IF NOT EXISTS device_information TEXT;
  `,
};
