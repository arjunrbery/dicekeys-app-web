
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

