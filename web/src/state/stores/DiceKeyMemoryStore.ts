import {
  diceKeyFacesFromHumanReadableForm, DiceKeyInHumanReadableForm, DiceKeyWithKeyId, DiceKeyWithoutKeyId, PublicDiceKeyDescriptor
} from "../../dicekeys/DiceKey";
import { action, makeAutoObservable, ObservableMap} from "mobx";
import { AllAppWindowsAndTabsAreClosingEvent } from "../core/AllAppWindowsAndTabsAreClosingEvent";
import { CustomEvent } from "../../utilities/event";
import { RUNNING_IN_ELECTRON } from "../../utilities/is-electron";
import { EncryptedDiceKeyStore, sortPublicDiceKeyDescriptors } from "./EncryptedDiceKeyStore";
import { writeStringToEncryptedLocalStorageField, readStringFromEncryptedLocalStorageField } from "../core/EncryptedStorageFields";

export interface PublicDiceKeyDescriptorWithSavedOnDevice extends PublicDiceKeyDescriptor {
  savedOnDevice: boolean
};

export const PlatformSupportsSavingToDevice = RUNNING_IN_ELECTRON;

interface StorageFormat {
  keyIdToDiceKeyInHumanReadableForm: [string, DiceKeyInHumanReadableForm][];
  centerLetterAndDigitToKeyId: [string, string][];
}

class DiceKeyMemoryStoreClass {
  static readonly StorageFieldName = "DiceKeyStore";
  // Because this class is saved using autoSaveEncrypted, all
  // files must be exposed (no proviate # fields) and must be 
  // classic JavaScript objects (no maps or observable maps)
  private keyIdToDiceKeyInHumanReadableForm = new ObservableMap<string, DiceKeyInHumanReadableForm>();
  private centerLetterAndDigitToKeyId = new ObservableMap<string, string>();

  #readyEvent = new CustomEvent(this);
  #isReady = RUNNING_IN_ELECTRON;

  #triggerReadyState = action( () => {
    if (!this.#isReady) {
      this.#isReady = true;
      this.#readyEvent.send()
    }
  });

  onReady = (callback: () => any) => {
    if (this.#isReady) {
      callback();
    } else {
      this.#readyEvent.onOnce( callback );
    }
  }

  toStorageFormat = (): StorageFormat => ({
    keyIdToDiceKeyInHumanReadableForm: [...this.keyIdToDiceKeyInHumanReadableForm.entries()],
    centerLetterAndDigitToKeyId: [...this.centerLetterAndDigitToKeyId.entries()]
  });
  toStorageFormatJson = () => JSON.stringify(this.toStorageFormat())

  updateStorage = () => {
    if (!RUNNING_IN_ELECTRON) {
      writeStringToEncryptedLocalStorageField(DiceKeyMemoryStoreClass.StorageFieldName, this.toStorageFormatJson());
    }
  }

  onReadFromShortTermEncryptedStorage = action ( (s: StorageFormat) => {
    this.keyIdToDiceKeyInHumanReadableForm = new ObservableMap(s.keyIdToDiceKeyInHumanReadableForm);
    this.centerLetterAndDigitToKeyId = new ObservableMap(s.centerLetterAndDigitToKeyId);
  });

  /**
   * Adds a DiceKey to the memory store, ensuring that it is rotated so that the middle face is upright.
   * It returns the DiceKey with the middle face upright.
   */
  addDiceKeyWithKeyId = action ( (diceKey: DiceKeyWithKeyId): DiceKeyWithKeyId => {
    const diceKeyWithCenterFaceUpright = diceKey.rotateToTurnCenterFaceUpright();
    if (!(diceKeyWithCenterFaceUpright.keyId in this.diceKeyForKeyId)) {
      this.keyIdToDiceKeyInHumanReadableForm.set(diceKeyWithCenterFaceUpright.keyId, diceKeyWithCenterFaceUpright.inHumanReadableForm);
      // Append the letter/digit to the end of the array (or start a new array)
      if (!(diceKeyWithCenterFaceUpright.centerLetterAndDigit in this.centerLetterAndDigitToKeyId)) {
        this.centerLetterAndDigitToKeyId.set(diceKeyWithCenterFaceUpright.centerLetterAndDigit, diceKeyWithCenterFaceUpright.keyId);
      }
    }
    this.updateStorage();
    return diceKeyWithCenterFaceUpright;
  });

  private loadFromDeviceStorage = async (...params: Parameters<typeof EncryptedDiceKeyStore.load>) : Promise<DiceKeyWithKeyId | undefined> => {
    if (!RUNNING_IN_ELECTRON)  return;
    const diceKeyWithKeyId = await EncryptedDiceKeyStore.load(...params);
    if (diceKeyWithKeyId != null && this.keyIdToDiceKeyInHumanReadableForm.has(diceKeyWithKeyId.keyId)) {
      // This DiceKey was not in the memory store, and should be added.
      this.addDiceKeyWithKeyId(diceKeyWithKeyId);
    }
    return diceKeyWithKeyId;
  }

  /**
   * Load a DiceKey either from memory (all platforms) or long-term storage
   * (Electron)
   * 
   * @param descriptor A public descriptor storing a DiceKey
   * @returns 
   */
  load = async (descriptor: PublicDiceKeyDescriptorWithSavedOnDevice): Promise<DiceKeyWithKeyId | undefined> => {
    const {keyId, savedOnDevice} = descriptor;
    const diceKeyInHumanReadableForm = this.keyIdToDiceKeyInHumanReadableForm.get(keyId);
    if (diceKeyInHumanReadableForm != null) {
      return new DiceKeyWithKeyId(keyId, diceKeyFacesFromHumanReadableForm(diceKeyInHumanReadableForm));
    } else if (savedOnDevice) {
      return await this.loadFromDeviceStorage(descriptor);
    }
    return;
  }

  addDiceKeyAsync = async (diceKey: DiceKeyWithoutKeyId): Promise<DiceKeyWithKeyId> => {
    return this.addDiceKeyWithKeyId(await diceKey.withKeyId);
  }

  saveToDeviceStorage = async (diceKey: DiceKeyWithKeyId) => {
    if (RUNNING_IN_ELECTRON) {
      await EncryptedDiceKeyStore.add(diceKey)
    }
  }

  removeDiceKeyForKeyId = action ( (keyId: string) => {
    // console.log(`removeDiceKeyForKeyId(${keyId})`);
    this.keyIdToDiceKeyInHumanReadableForm.delete(keyId);
    this.updateStorage();
  });

  removeDiceKey = async (diceKeyOrKeyId: DiceKeyWithKeyId | string) => {
    const keyId = typeof(diceKeyOrKeyId) === "string" ? diceKeyOrKeyId : diceKeyOrKeyId.keyId;
    this.removeDiceKeyForKeyId(keyId);
  };

  deleteKeyIdFromDeviceStorageAndMemory = (keyId: string) => {
    this.removeDiceKeyForKeyId(keyId)
    EncryptedDiceKeyStore.delete({keyId})
  }

  removeAll = action ( () => {
    // console.log(`Remove all`);
    this.keyIdToDiceKeyInHumanReadableForm.clear();
    this.centerLetterAndDigitToKeyId.clear();
    this.updateStorage();
  });

  get keyIds(): string[] { return [...this.keyIdToDiceKeyInHumanReadableForm.keys()] }

  hasKeyIdInMemory = (keyId: string) => this.keyIdToDiceKeyInHumanReadableForm.has(keyId);

  hasKeyInEncryptedStore = (keyId: string) => EncryptedDiceKeyStore.has({keyId});

  get keysInMemory(): PublicDiceKeyDescriptorWithSavedOnDevice[] {
    return sortPublicDiceKeyDescriptors([...(this.keyIdToDiceKeyInHumanReadableForm.entries())].map( ([keyId, diceKeyInHumanReadableForm]) => {
      const {centerFace} = new DiceKeyWithoutKeyId(diceKeyFacesFromHumanReadableForm(diceKeyInHumanReadableForm));
      return {
        keyId,
        centerFaceDigit: centerFace.digit,
        centerFaceLetter: centerFace.letter,
        savedOnDevice: RUNNING_IN_ELECTRON && EncryptedDiceKeyStore.has({keyId})
      }
    }));
  }

  get keysSavedToDeviceButNotInMemory(): (PublicDiceKeyDescriptorWithSavedOnDevice & {savedOnDevice: true})[] {
    return RUNNING_IN_ELECTRON ? (
      EncryptedDiceKeyStore.storedDiceKeys
        // remove keys already in memory
        .filter( ({keyId}) => !this.keyIdToDiceKeyInHumanReadableForm.has(keyId) )
        // augment record to indicate these keys are saved on the device
        .map( x => ({...x, savedOnDevice: true}) )
    ) :
      [];
  }

  get keysInMemoryOrSavedToDevice(): PublicDiceKeyDescriptorWithSavedOnDevice[] {
    return [...this.keysInMemory, ...this.keysSavedToDeviceButNotInMemory];
  }

  get isNonEmpty(): boolean { return this.keyIds.length > 0 }

  get keysIdsAndNicknames() {
    return [...this.keyIdToDiceKeyInHumanReadableForm.entries()]
      .map( ([keyId, diceKeyInHumanReadableForm]) =>
        ({keyId, nickname: DiceKeyWithoutKeyId.fromHumanReadableForm(diceKeyInHumanReadableForm).nickname })
      );
  }
 
  diceKeyForKeyId = (keyId: string | undefined): DiceKeyWithKeyId | undefined => {
    if (keyId == null) return;
    const result = this.keyIdToDiceKeyInHumanReadableForm.get(keyId);
    // console.log(`${keyId} ${result} from ${JSON.stringify(toJS(this.diceKeysByKeyId))} `);
    if (typeof result === "string") {
      return new DiceKeyWithKeyId(keyId, diceKeyFacesFromHumanReadableForm(result));
    }
    return;
  }

  keyIdForCenterLetterAndDigit = (centerLetterAndDigit: string): string | undefined =>
    this.centerLetterAndDigitToKeyId.get(centerLetterAndDigit);

  #initiateReadFromLocalStorage = async () => {
    try {
      const json = await readStringFromEncryptedLocalStorageField(DiceKeyMemoryStoreClass.StorageFieldName);
      if (json == null) {
        console.log("No DiceKeys in memory store");
        return;
      }
      if (json) {
        const storageFormat = JSON.parse(json) as StorageFormat;
        this.onReadFromShortTermEncryptedStorage(storageFormat);
        
        console.log(`Read ${storageFormat.keyIdToDiceKeyInHumanReadableForm.length} DiceKey(s) from memory`)
      }
    } catch {
      console.log("Problem reading DiceKeys from memory store")
    }
    this.#triggerReadyState();
  }

  constructor() {
    makeAutoObservable(this);
    if (!RUNNING_IN_ELECTRON) {
      // We don't need to save the DiceKeyStore in electron because there is only one window right now
      // and there's no chance of a refresh.
      this.#initiateReadFromLocalStorage();
    }
    AllAppWindowsAndTabsAreClosingEvent.on( () => {
      // Empty the store if all app windows are closing.
      this.removeAll();
    })
  }
}
export const DiceKeyMemoryStore = new DiceKeyMemoryStoreClass();