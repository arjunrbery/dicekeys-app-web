import usbDetect from "usb-detection";

/**
 * If you are polling devices() or doing repeated new HID.HID(vid,pid) to detect device plug / unplug,
 * consider instead using node-usb-detection. node-usb-detection uses OS-specific,
 * non-bus enumeration ways to detect device plug / unplug.
 */

export type Device = usbDetect.Device;
export type DeviceListUpdateCallback = (devices: Device[]) => any;
export type ErrorCallback = (error: any) => any;
export type StopMonitoringFunction = () => void;

const getDeviceKey = (device: Device): string =>
  `${ device.productId ?? ""}:${ device.vendorId ?? ""}:${ device.serialNumber ?? "" }`

/**
 * A static class that tracks the set of seedable FIDO keys
 * connected via USB
 */
export class UsbDeviceMonitor {
  /**
   * A set of callbacks to notify when the device list changes
   */
  private _errorOnFindDevices: any;
  public get errorOnFindDevices() {return this._errorOnFindDevices}
  private deviceMap = new Map<string, Device>();
  private onDeviceListChangedCallbacks: Set<DeviceListUpdateCallback> = new Set();
  private _findDevicesResult?: Promise<Device[]>;
//  public get findDevicesResult() { return this._findDevicesResult }

  private findDevices = async (): Promise<Device[]> => {
    try {
      const devices = (await usbDetect.find());
      const filteredDevices = devices.filter(this.deviceFilter);
      for (const device of filteredDevices) {
        this.deviceMap.set(getDeviceKey(device), device)
      }
      this.notifyOnKeysChangedListeners();
      return filteredDevices;
    } catch (e) {
      this._errorOnFindDevices = e;
      throw e;
    }
  }

  /**
   * Starts monitoring for the addition/deletion of USB devices,
   * receiving a list of devices to the callback whenever the list is
   * first available after the call and anytime it changes after.
   *
   * The caller must call stopMonitoring (the function returned by startMonitoring)
   * when done listening for HID events or the process will be unable to terminate.
   * @param deviceListUpdateCallback 
   * @returns A stopMonitoring function which must be called when the caller
   * no longer needs to monitor for changes to the list of USB devices.
   * If this is not called, the process will be unable to exit.
   */
  startMonitoring = (deviceListUpdateCallback: DeviceListUpdateCallback, errorCallback?: ErrorCallback): StopMonitoringFunction => {
    if (this.onDeviceListChangedCallbacks.size == 0) {
      this.onDeviceListChangedCallbacks.add(deviceListUpdateCallback);
      usbDetect.startMonitoring();
      usbDetect.on("add", this.addDevice);
      usbDetect.on("remove", this.removeDevice)  
      this._findDevicesResult = this.findDevices();
    } else {
      this.onDeviceListChangedCallbacks.add(deviceListUpdateCallback);
      const {devices} = this;
      if (devices.length > 0) {
        deviceListUpdateCallback(devices);
      }
    }
    this._findDevicesResult?.catch( e => errorCallback?.(e) );
    return this.stopMonitoring(deviceListUpdateCallback);
  }
  
  private stopMonitoring = (callback: DeviceListUpdateCallback) => () => {
    this.onDeviceListChangedCallbacks.delete(callback);
    if (this.onDeviceListChangedCallbacks.size == 0) {
      usbDetect.stopMonitoring();
    }
  }

  private addDevice = (device: Device) => {
    if (this.deviceFilter(device)) {
      this.deviceMap.set(getDeviceKey(device), device);
      this.notifyOnKeysChangedListeners();
    }
  }

  private removeDevice = (device: Device) => {
    if (this.deviceFilter(device)) {
      this.deviceMap.delete(getDeviceKey(device));
      this.notifyOnKeysChangedListeners();
    }
  }

  constructor(
    private deviceFilter: (device: Device) => boolean
  ) {}


  private _requiresPermission: boolean = true;
  public get requiresPermission(): boolean { return this._requiresPermission; }

  /**
   * Notify all the listeners waiting for updates to the device list.
   */
  private notifyOnKeysChangedListeners = () => {
    const keys = this.devices;
    for (const callback of [...this.onDeviceListChangedCallbacks]) {
      callback(keys);
    }
  }

  /**
   * An array potential seedable FIDO keys connected to this device.
   */
  public get devices(): Device[] {
    return [...this.deviceMap.keys()].sort().map( k => this.deviceMap.get(k)! )
  } 

}

