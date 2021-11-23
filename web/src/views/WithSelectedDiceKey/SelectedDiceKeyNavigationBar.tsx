import { observer } from "mobx-react";
import React from "react";
import { RUNNING_IN_ELECTRON, ValuesDefinedOnlyWhenRunningElectron } from "../../utilities/is-electron";
import { addressBarState } from "../../state/core/AddressBarState";
import {
  TopNavigationBar,
  TopNavLeftSide, TopNavCenter, TopNavRightSide
} from "../Navigation/TopNavigationBar";
import { SelectedDiceKeyViewProps } from "./SelectedDiceKeyViewProps";
import { EncryptedDiceKeyStore } from "../../state/stores/EncryptedDiceKeyStore";
import { DiceKeyWithKeyId } from "../../dicekeys/DiceKey";
import { DiceKeysNavHamburgerMenu, ExpandableMenuProps, HamburgerMenuButton, MenuItem } from "../Navigation/Menu";
import { BooleanState } from "../../state/reusable/BooleanState";

type ElectronOnlyValues = {
  onBackButtonClicked: () => any;
  onSaveDeleteButtonClicked: () => any;
  isSaved: boolean;
};

const handleOnSaveDeleteButtonClicked = (isSaved: boolean, diceKey: DiceKeyWithKeyId): (() => Promise<void>) =>
  isSaved ?
    (() => EncryptedDiceKeyStore.delete(diceKey)) :
    (() => EncryptedDiceKeyStore.add(diceKey));


const SelectedDiceKeyExpandableHamburgerMenu = observer( ( {
  state,
  booleanStateTrueIfMenuExpanded
//  goBack
}: SelectedDiceKeyViewProps & ExpandableMenuProps) => {
  const diceKey = state.foregroundDiceKeyState.diceKey;
  if (diceKey == null) return null;

  const isSaved = EncryptedDiceKeyStore.has(diceKey);
  const onSaveDeleteButtonClicked = handleOnSaveDeleteButtonClicked(isSaved, diceKey)

  return (
    <DiceKeysNavHamburgerMenu {...{booleanStateTrueIfMenuExpanded}}>
      <MenuItem onClick={onSaveDeleteButtonClicked}>{ isSaved ? `Delete` : `Save`}</MenuItem>
    </DiceKeysNavHamburgerMenu>
  );
});

export const SelectedDiceKeyNavigationBar = observer( ( {
  state,
  goBack
}: SelectedDiceKeyViewProps) => {
  // Make the top left nav bar a button iff we're running in electron,
  // otherwise we're in the browser and this should be a no-op (undefined onClick handler)
  // as the web-based app relies on the back button within the browser.
  const diceKey = state.foregroundDiceKeyState.diceKey;
  if (diceKey == null) return null;

  const getElectronOnlyValues: () => ElectronOnlyValues = () => {
    const isSaved = EncryptedDiceKeyStore.has(diceKey);
    return {
      onBackButtonClicked: goBack ?? addressBarState.back,
      onSaveDeleteButtonClicked: handleOnSaveDeleteButtonClicked(isSaved, diceKey),
      isSaved,
    };
  };
  const booleanStateTrueIfMenuExpanded = new BooleanState();

  const {
    onBackButtonClicked,
    onSaveDeleteButtonClicked,
    isSaved,
  } = (RUNNING_IN_ELECTRON ? getElectronOnlyValues() : {}) as ValuesDefinedOnlyWhenRunningElectron<ElectronOnlyValues>;

  return (<>
    {
        RUNNING_IN_ELECTRON ? (<SelectedDiceKeyExpandableHamburgerMenu {...{booleanStateTrueIfMenuExpanded, state, goBack}} />) : null 
    }
    <TopNavigationBar>
      <TopNavLeftSide onClick={ onBackButtonClicked } >{
        RUNNING_IN_ELECTRON ?
          // Show a back button in Electron
          (<>&#8592;</>) :
          // Don't show a back button for the web app, as the browser back button will work.
          (<></>)
        }</TopNavLeftSide>
      <TopNavCenter>{diceKey?.nickname ?? ""}</TopNavCenter>
      <TopNavRightSide >{
        RUNNING_IN_ELECTRON ? (<HamburgerMenuButton {...{booleanStateTrueIfMenuExpanded}}></HamburgerMenuButton>) : null 
      }</TopNavRightSide>
    </TopNavigationBar>
  </>)
});