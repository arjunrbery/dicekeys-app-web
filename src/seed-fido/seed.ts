import { getRandomBytes } from "~dicekeys/get-random-bytes";


const seedableDeviceFilters: HIDDeviceFilter[] = [
  {
    vendorId: 0x10c4,
    productId: 0x8acf,
  },
  {
    vendorId: 0x483,
    productId: 0xa2ca,
  },
]
const getFidoKeyDeviceId = (device: HIDDevice): string =>
  `${ device.productId ?? ""}:${ device.vendorId ?? ""}:${ device.productName ?? "" }`

export class SeedableFidoKeys {
  private static keys: Map<string, HIDDevice> = ((): Map<string, HIDDevice> => {
    document.addEventListener('DOMContentLoaded', async () => {
      
      const devices = await navigator.hid.requestDevice({filters: seedableDeviceFilters});
      for (const device of devices ) {
        SeedableFidoKeys.keys.set(getFidoKeyDeviceId(device), device)
      }
    });

    navigator.hid.addEventListener('connect', ({device}) => {
      SeedableFidoKeys.keys.set(getFidoKeyDeviceId(device), device)
    });
    
    navigator.hid.addEventListener('disconnect', ({device}) => {
      SeedableFidoKeys.keys.delete(getFidoKeyDeviceId(device))
    });
    return new Map<string, HIDDevice>();
  })();
}


const BroadcastChannel = 0xffffffff;

const HIDCommands = {
  CTAPHID_MSG: 0x03,
  CTAPHID_INIT: 0x06,
  CTAPHID_WINK: 0x08,
  CTAPHID_ERROR: 0x3F,
  CTAPHID_LOADKEY: 0x62,
} as const;

// const Defaults = {
//   TIMEOUT_MS: 500,
//   RETRIES: 5,
//   RETRY_TIMEOUT_MS: 100
// } as const;

// In DataView, set BigEndian by sending false to the littleEndian field.
const makeBigEndianPassingFalseForLittleEndian = false;

const CTAP2_ERR_OPERATION_DENIED = 0x27;


const hidPacketLengthInBytes = 64


/// This class decodes CTAP HID packets received from a security key
class CtapHidPacketReceived {

  /// Construct this class to decode the values in a CTAP HID Packet
  /// - Parameter packet: the raw HID packet received
  constructor(private readonly packet: DataView) {
  }

  get headerSizeInBytes(): number {
    return this.isInitializationPacket ? 7 : 5
  }
  get channel(): number {
    return this.packet.getUint32(0, makeBigEndianPassingFalseForLittleEndian)
  }

  get commandByte(): number {
    return this.packet.getUint8(4);
  }
  get isInitializationPacket(): boolean {
    return (this.commandByte & 0x80) != 0
  }
  
  get command(): number {
    return this.channel & 0x7f
  }

  get length(): number {
    return this.isInitializationPacket ?
        this.packet.getUint16(5, makeBigEndianPassingFalseForLittleEndian) :
        (hidPacketLengthInBytes - this.headerSizeInBytes)
  }
  get message(): DataView {
    return new DataView(this.packet.buffer.slice(this.headerSizeInBytes))
  }
}

/// A class used to decode the contents of an HID INIT response
class CtapHidInitResponseMessage {
  /// Decode an HID INIT response message from the data within the response
  /// - Parameter message: The data encoded in the packet
  constructor(private readonly message: DataView) {}
  
  // DATA    8-byte nonce
  get nonce(): ArrayBuffer {
    return this.message.buffer.slice(8, 16);
  }

  // DATA+8    4-byte channel ID
  get channelCreated(): number {
    return this.message.getUint32(8, makeBigEndianPassingFalseForLittleEndian);
  }

  // DATA+12    CTAPHID protocol version identifier
  get ctapProtocolVersionIdentifier(): number{ return this.message.getInt8(12) }
  // DATA+13    Major device version number
  get majorDeviceVersionNumber(): number{ return this.message.getInt8(13) }
  // DATA+14    Minor device version number
  get minorDeviceVersionNumber(): number{ return this.message.getInt8(14) }
  // DATA+15    Build device version number
  get buildDeviceVersionNumber(): number{ return this.message.getInt8(15) }
  // DATA+16    Capabilities flags
  get capabilitiesFlags(): number{ return this.message.getInt8(16) }
}

const sendCtapHidMessage = async (device: HIDDevice, channel: number, command: number, data: DataView): Promise<void> => {
  /*
   *            INITIALIZATION PACKET
   *            Offset   Length    Mnemonic    Description
   *            0        4         CID         Channel identifier
   *            4        1         CMD         Command identifier (bit 7 always set)
   *            5        1         BCNTH       High part of payload length
   *            6        1         BCNTL       Low part of payload length
   *            7        (s - 7)   DATA        Payload data (s is equal to the fixed packet size)
   */
  // Create a zero-filled packet
  const initializationPacketArray = new Uint8Array(hidPacketLengthInBytes)
  const initializationPacket = new DataView(initializationPacketArray);
  initializationPacket.setUint32(0, channel, makeBigEndianPassingFalseForLittleEndian);
  initializationPacket.setUint8(4, command | 0x80);
  initializationPacket.setUint16(5, data.byteLength, makeBigEndianPassingFalseForLittleEndian);
  let dest = 7, src = 0, packetSequenceByte = 0;
  // Copy the data
  while (dest < hidPacketLengthInBytes && src < data.byteLength) {
    initializationPacket.setUint8(dest++, data.getUint8(src++));
  }
  await device.sendReport(0, initializationPacket);

  while(src < data.byteLength && packetSequenceByte < 0x80) {
      /**
       *  CONTINUATION PACKET
       *  Offset    Length    Mnemonic  Description
       *  0         4         CID       Channel identifier
       *  4         1         SEQ       Packet sequence 0x00..0x7f (bit 7 always cleared)
       *  5         (s - 5)   DATA      Payload data (s is equal to the fixed packet size)
       */
      dest = 5;
      const continuationPacketArray = new Uint8Array(hidPacketLengthInBytes)
      const continuationPacket = new DataView(continuationPacketArray);
      continuationPacket.setUint32(0, channel, makeBigEndianPassingFalseForLittleEndian);
      continuationPacket.setUint8(4, packetSequenceByte);
      // Copy the data
      while (dest < hidPacketLengthInBytes && src < data.byteLength) {
        continuationPacket.setUint8(dest++, data.getUint8(src++));
      }
      await device.sendReport(0, continuationPacket);
    }
}

const getChannel = (device: HIDDevice): Promise<number> => 
  new Promise<number>( (resolve, reject) => {
    let channelCreationNonce = getRandomBytes(8)
    
    // console.log("Sent channel request with nonce \([UInt8](channelCreationNonce))")

    const receiveEvent = (event: HIDInputReportEvent) => {
      const packet = new CtapHidPacketReceived(event.data);
      const message = new CtapHidInitResponseMessage(packet.message);
      // FIXME -- if nonce doesn't match then do nothing and wait for next call
      const channelCreated = message.channelCreated;  
      device.removeEventListener("inputreport", receiveEvent);
      resolve(channelCreated);
    }
    device.addEventListener("inputreport", receiveEvent);

    try {
      sendCtapHidMessage(device, BroadcastChannel, HIDCommands.CTAPHID_INIT, new DataView(channelCreationNonce));
    } catch (e) {
      reject (e);
    }
  });

const sendWriteMessage = async (device: HIDDevice, channel: number, seed: Uint8Array, extState: Uint8Array): Promise<void> => 
  new Promise<void>( (resolve, reject) => {
    const commandVersion = 1;
    // FIXME -- verify order is correct (it matches iOS ordering, also check Android)
    if (seed.length != 32) {
      // FIXME - reject
    }

    const receiveEvent = (event: HIDInputReportEvent) => {
      const packet = new CtapHidPacketReceived(event.data);
      // FIXME -- if nonce doesn't match then do nothing and wait for next call
      device.removeEventListener("inputreport", receiveEvent);
      if (packet.command == HIDCommands.CTAPHID_LOADKEY) {
        resolve()
      } else if (packet.command == HIDCommands.CTAPHID_ERROR) {
        reject(packet.message)
      }
    }
    device.addEventListener("inputreport", receiveEvent);

    const message = new Uint8Array([commandVersion, ...seed, ...extState]);
    try {
      sendCtapHidMessage(device, channel, HIDCommands.CTAPHID_LOADKEY, new DataView(message))
    } catch (e) {
      reject(e);
    }
  });

export const writeSoloKey = async (device: HIDDevice, seed: Uint8Array, extState: Uint8Array = new Uint8Array(0)) => {
  await device.open();
  try {
    const channel = await getChannel(device);
    return await sendWriteMessage(device, channel, seed, extState);
  } finally {
    device.close()
  }
}
