import React from "react";
import {observer} from "mobx-react";
import {
  CamerasOnThisDevice
} from "./CamerasOnThisDevice";
import styled from "styled-components";

const CameraNameDiv = styled.div`
  color: green;
  font-size: 1.25rem;
`;
// export interface CamerasBeingInspectedOptions extends React.Props{}

const CameraOnThisDevice = styled.div``;
const CameraFound = styled(CameraOnThisDevice)``;
const CameraUnreadable = styled(CameraOnThisDevice)``;
const CameraToBeAdded = styled(CameraOnThisDevice)``;

// FIXME, class names below are no-ops.
export const CamerasBeingInspected = observer( () => {
  const camerasOnThisDevice = CamerasOnThisDevice.instance;
  return (
    <CameraNameDiv>
      <div key="heading">Identifying device cameras...</div>
      { camerasOnThisDevice.cameras.map( (camera) => (
          <CameraFound key={camera.deviceId} >{camera.name}</CameraFound>
        ))
      }
      { [...camerasOnThisDevice.unreadableCameraDevices.values()].map( ({cameraDevice}) => (
          <CameraUnreadable key={cameraDevice.deviceId}>{cameraDevice.label ?? cameraDevice.deviceId}</CameraUnreadable>
        ))
      }
      { [...camerasOnThisDevice.camerasToBeAdded.values()].map( (camera) => (
          <CameraToBeAdded key={camera.deviceId}>{camera.label ?? camera.deviceId}</CameraToBeAdded>
        ))
      }
    </CameraNameDiv>
  )
});
