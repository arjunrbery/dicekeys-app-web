import { observer } from "mobx-react";
import React from "react";
import {WindowTopLevelNavigationState as WindowTopLevelNavigationState} from "../state/Window";
import { SelectedDiceKeyViewStateName } from "./WithSelectedDiceKey/SelectedDiceKeyViewState";
import { SelectedDiceKeyView } from "./WithSelectedDiceKey/SelectedDiceKeyView";
import { WindowHomeView } from "./WindowHomeView";
import { LoadDiceKeyFullPageView, LoadDiceKeyViewStateName } from "./LoadingDiceKeys/LoadDiceKeyView";
import {AssemblyInstructionsView} from "./AssemblyInstructionsView"
import { AssemblyInstructionsStateName } from "./AssemblyInstructionsState";
import {ApproveApiRequestState, ApproveApiRequestView} from "./api-request-handling/ApproveApiRequestView";
import { ApiRequestsReceivedState } from "../state/ApiRequestsReceivedState";
import { PrimaryView } from "../css";
import { SeedHardwareKeyFullPageView } from "./Recipes/SeedHardwareKeyView";
import { SeedHardwareKeyViewStateName } from "./Recipes/SeedHardwareKeyViewState";
import { SaveDiceKeyViewStateName, SaveDiceKeyToDeviceStorageView, DeleteDiceKeyViewStateName, DeleteDiceKeyToDeviceStorageView } from "./SaveAndDeleteDiceKeyView";
import { RUNNING_IN_ELECTRON } from "../utilities/is-electron";

export const WindowRoutingView = observer ( ({windowTopLevelNavigationState}: {windowTopLevelNavigationState: WindowTopLevelNavigationState}) => {

  const {foregroundApiRequest} = ApiRequestsReceivedState;
  if (foregroundApiRequest != null) {
    return (
      <ApproveApiRequestView state={new ApproveApiRequestState(foregroundApiRequest)}
        onApiRequestResolved={ApiRequestsReceivedState.dequeueApiRequestReceived}
      />
    )
  }
  // console.log(`Displaying subview ${windowTopLevelNavigationState.subView}`)
  const {subViewState} = windowTopLevelNavigationState.subView;
  console.log(`Re-rendering top level switch for view name ${subViewState?.viewName}`);
  switch (subViewState?.viewName) {
    case SaveDiceKeyViewStateName:
      return (<SaveDiceKeyToDeviceStorageView state={subViewState} />);
    case DeleteDiceKeyViewStateName:
      return (<DeleteDiceKeyToDeviceStorageView state={subViewState} />);
    case LoadDiceKeyViewStateName:
      return (
        <LoadDiceKeyFullPageView
          onDiceKeyReadOrCancelled={ windowTopLevelNavigationState.onReturnFromActionThatMayLoadDiceKey }
          state={ subViewState }
        />
      );
    case AssemblyInstructionsStateName:
      return (
        <AssemblyInstructionsView onComplete={ windowTopLevelNavigationState.onReturnFromActionThatMayLoadDiceKey } state={subViewState}
//          new AssemblyInstructionsState(windowTopLevelNavigationState.foregroundDiceKeyState)
         />
    )
    case SeedHardwareKeyViewStateName: return (
      <SeedHardwareKeyFullPageView seedHardwareKeyViewState={subViewState} />
    );
    case SelectedDiceKeyViewStateName: return (
      <SelectedDiceKeyView state={subViewState} />
    );
    default: return (
      <WindowHomeView state={windowTopLevelNavigationState} />
    );
  }
});

const defaultWindowNavigationState = RUNNING_IN_ELECTRON ?
      new WindowTopLevelNavigationState() : WindowTopLevelNavigationState.fromPath();

export const WindowTopLevelView = observer ( ({
  windowTopLevelNavigationState = defaultWindowNavigationState } : {
  windowTopLevelNavigationState?: WindowTopLevelNavigationState
}) => (
  <PrimaryView>
    <WindowRoutingView {...{windowTopLevelNavigationState}} />
  </PrimaryView>
));
