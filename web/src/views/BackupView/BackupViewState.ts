import { DiceKeyWithKeyId } from "../../dicekeys/DiceKey";
import { action, makeAutoObservable } from "mobx";
import { BackupMedium } from "./BackupMedium";
import { ValidateBackupViewState } from "./ValidateBackupViewState";
import { BaseViewState } from "../../state/core/ViewState";
import { SettableOptionalDiceKey, WithDiceKey } from "../../state/Window/DiceKeyState";

export enum BackupStep {
  SelectBackupMedium = 1,
  Introduction,
  FirstFace,
  LastFace = FirstFace + 24,
  Validate,
  END_EXCLUSIVE,
  START_INCLUSIVE = 1,
}

const validStepOrUndefined = (step: number): BackupStep | undefined =>
  (step >= BackupStep.START_INCLUSIVE && step < BackupStep.END_EXCLUSIVE) ? step : undefined;

// interface SettableDiceKeyState {
//   diceKey?: DiceKey,
//   setDiceKey: (diceKey?: DiceKey) => any;
// }

export const BackupViewStateName = "backup";
export class BackupViewState extends BaseViewState<typeof BackupViewStateName> {
  constructor(
    basePath: string,
    readonly withDiceKey: SettableOptionalDiceKey | WithDiceKey,
    public step: BackupStep = BackupStep.START_INCLUSIVE
  ) {
    super(BackupViewStateName, basePath);
    this.validationStepViewState = new ValidateBackupViewState(this.withDiceKey);
    makeAutoObservable(this);
  }

  get path(): string { return `${this.basePath}/${this.viewName}/${this.step != BackupStep.START_INCLUSIVE ? this.step : ""}` };

  /**
   * 
   * @param diceKey The DiceKey of the selected state
   * @param subPathElements The elements of the address bar split by forward slashes, with the elements
   * for the parent views removed, such that
   * the path `/M1/backup/3` would result in the `fromPathElements` array of `["backup", "3"]`.
   */
  static fromPath = (diceKey: DiceKeyWithKeyId, basePath: string, subPathElements: string[] = []): BackupViewState => {
    const pathStep = subPathElements.length < 2 ? BackupStep.START_INCLUSIVE : parseInt(subPathElements[1] ?? "${BackupStep.START_INCLUSIVE}");
    const step = pathStep >= BackupStep.START_INCLUSIVE && pathStep < BackupStep.END_EXCLUSIVE ? pathStep : BackupStep.START_INCLUSIVE;
    return new BackupViewState( basePath, {diceKey}, step);
  }

  validationStepViewState: ValidateBackupViewState;
  backupMedium?: BackupMedium;
//  diceKeyScannedFromBackup = DiceKeyWithoutKeyId;

  setBackupMedium = (newMedium: BackupMedium) => action ( () => {
    this.backupMedium = newMedium;
    this.step = BackupStep.SelectBackupMedium + 1;
  });
  setStep = action ( (step: BackupStep) => {
    if (step === BackupStep.Validate) {
      // If moving to the validation step, and if we had tried scanning a key to validate before,
      // clear what we scanned
//      this.diceKeyScannedFromBackup.clear();
      this.validationStepViewState.clear();
    }
    this.step = step;
  });
  setStepTo = (step?: BackupStep) => step == null ? undefined : () => this.setStep(step);
  get stepPlus1() {
    return validStepOrUndefined(this.step+1)
  }
  get stepMinus1() { return validStepOrUndefined(this.step-1) }

  userChoseToSkipValidationStep: boolean = false;
  setUserChoseToSkipValidationStep = action ( () => this.userChoseToSkipValidationStep = true );

  clear = action ( () => {
    this.backupMedium = undefined;
    this.step = BackupStep.START_INCLUSIVE;
  })

}