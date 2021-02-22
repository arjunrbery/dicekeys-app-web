const isSeedable = ({vendorId, productId}: HIDDevice): boolean =>
  (vendorId == 0x10c4 && productId == 0x8acf) ||
  (vendorId == 0x483 && productId == 0xa2ca);
  
// const seedableDeviceFilters: HIDDeviceFilter[] = [
  // {
  //   vendorId: 0x10c4,
  //   productId: 0x8acf,
  // },
  // {
  //   vendorId: 0x483,
  //   productId: 0xa2ca,
  // },
// ]
const getFidoKeyDeviceId = (device: HIDDevice): string =>
  `${ device.productId ?? ""}:${ device.vendorId ?? ""}:${ device.productName ?? "" }`

/**
 * A static class that tracks the set of seedable FIDO keys
 * connected via USB
 */
export class SeedableFidoKeys {
  private static _requiresPermission: boolean = true;
  public static get requiresPermission(): boolean { return SeedableFidoKeys._requiresPermission; }
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

  public static tryLoadKeys = async () => {
      // Request access to and get a listed of USB devices that meet our filters
      // for identifying seedable FIDO keys.
      try {
        const devices = await navigator.hid.requestDevice({filters: []}); // {filters: seedableDeviceFilters});
        SeedableFidoKeys._requiresPermission = false;
        for (const device of devices ) {
          SeedableFidoKeys.keysMap.set(getFidoKeyDeviceId(device), device)
        }
        SeedableFidoKeys.notifyOnKeysChangedListeners();
      } catch {
      }
  }

  private static keysMap: Map<string, HIDDevice> = ((): Map<string, HIDDevice> => {
    document.addEventListener('DOMContentLoaded', SeedableFidoKeys.tryLoadKeys);

    navigator.hid.addEventListener('connect', ({device}) => {
      if (isSeedable(device)) {
        // Update the list if a new device is connected
        SeedableFidoKeys.keysMap.set(getFidoKeyDeviceId(device), device);
        SeedableFidoKeys.notifyOnKeysChangedListeners();
      }
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
  public static onKeysChangedStartListening = (callback: (keys: HIDDevice[]) => any) => {
    SeedableFidoKeys.onKeysChangedCallbacks.add(callback);
  }

  /**
   * Stop listening for changes to the set of connected potential seedable FIDO keys
   * @param callback The callback to remove
   */
  public static onKeysChangedStopListening = (callback: (keys: HIDDevice[]) => any) => {
    SeedableFidoKeys.onKeysChangedCallbacks.delete(callback);
  }

}

