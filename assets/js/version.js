// version.js
// Protocol registry — DO NOT break contracts casually

export const FORMATS = {
  BYTESEAL_V1: {
    id: "byteseal-v1",
    magic: "BYTESEAL",
    magicLen: 8,
    version: 1,
    label: "ByteSeal v1",
  },
};

export const ACTIVE_FORMAT = FORMATS.BYTESEAL_V1;