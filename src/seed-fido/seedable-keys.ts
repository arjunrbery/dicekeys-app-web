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

/**
 * A static class that tracks the set of seedable FIDO keys
 * connected via USB
 */
export class SeedableFidoKeys {
  /**
   * A set of callbacks to notify when the device list changes
   */
  private static onKeysChangedCallbacks: Set<(keys: HIDDevice[]) => any> = new Set();

  /**
   * Notify all the listeners waiting for updates to the device list.
   */
  private static notifyOnKeysChangedListeners = () => {
    const keys = SeedableFidoKeys.keys;
    for (const callback of [...SeedableFidoKeys.onKeysChangedCallbacks]) {
      callback(keys);
    }
  }

  private static keysMap: Map<string, HIDDevice> = ((): Map<string, HIDDevice> => {
    document.addEventListener('DOMContentLoaded', async () => {
 
      // Request access to and get a listed of USB devices that meet our filters
      // for identifying seedable FIDO keys.
      const devices = await navigator.hid.requestDevice({filters: seedableDeviceFilters});
      for (const device of devices ) {
        SeedableFidoKeys.keysMap.set(getFidoKeyDeviceId(device), device)
      }
      SeedableFidoKeys.notifyOnKeysChangedListeners();
    });

    navigator.hid.addEventListener('connect', ({device}) => {
      // Update the list if a new device is connected
      SeedableFidoKeys.keysMap.set(getFidoKeyDeviceId(device), device);
      SeedableFidoKeys.notifyOnKeysChangedListeners();
    });
    
    navigator.hid.addEventListener('disconnect', ({device}) => {
      // Update the list if a device is disconnected
      SeedableFidoKeys.keysMap.delete(getFidoKeyDeviceId(device));
      SeedableFidoKeys.notifyOnKeysChangedListeners();
    });
    return new Map<string, HIDDevice>();
  })();

  /**
   * An array potential seedable FIDO keys connected to this device.
   */
  public static get keys(): HIDDevice[] {
    return [...SeedableFidoKeys.keysMap.keys()].sort().map( k => SeedableFidoKeys.keysMap.get(k)! )
  } 

  /**
   * Listen for changes to the set of connected potential seedable FIDO keys
   * @param callback A callback which optionally receives the current list of keys
   */
  public onKeysChangedStartListening = (callback: (keys: HIDDevice[]) => any) => {
    SeedableFidoKeys.onKeysChangedCallbacks.add(callback);
  }

  /**
   * Stop listening for changes to the set of connected potential seedable FIDO keys
   * @param callback The callback to remove
   */
  public onKeysChangedStopListening = (callback: (keys: HIDDevice[]) => any) => {
    SeedableFidoKeys.onKeysChangedCallbacks.delete(callback);
  }

}

