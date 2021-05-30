import React from "react";
import { observer } from "mobx-react";
import { DiceKey, EmptyPartialDiceKey } from "../../dicekeys/DiceKey";
import { FaceGroupView } from "./FaceView";
import {portraitSheetWidthOverHeight, StickerSheetSizeModel} from "./StickerSheetView"
import { Bounds, viewBox } from "../../utilities/bounding-rects";
import { OptionalMaxSizeCalcProps, WithBounds } from "../../utilities/WithBounds";

const FaceTargetPlaceholderSvgGroup = (props: {linearSizeOfFace: number} & React.SVGAttributes<SVGGElement>) => {
  const {linearSizeOfFace, ...otherProps} = props;
  const centerWhiteSquareSize = linearSizeOfFace * 0.75;
  const darker = "#D0D0D0";
  const lighter = "#FEFEFE";
  const lightest = "#F8F8F8";
  const p1 = linearSizeOfFace/2;
  const p0 = -p1; 
  const style={stroke: darker, strokeWidth: linearSizeOfFace/40} as const;
  return (<g {...otherProps} >
  <line style={style}
    x1={0} x2={0}
    y1={p0} y2={p1}
  />
  <line style={style}
    x1={p0} x2={p1}
    y1={0} y2={0}
  />
  <line style={style}
    x1={p0} x2={p1}
    y1={p0} y2={p1}
  />
  <line style={style}
    x1={p0} x2={p1}
    y1={p1} y2={p0}
  />
  <rect
    x={-centerWhiteSquareSize/2} y={-centerWhiteSquareSize/2}
    height={centerWhiteSquareSize} width={centerWhiteSquareSize}
    style={{fill: lighter, stroke: lightest, strokeWidth: linearSizeOfFace/30}} />
  </g>)
}

type StickerTargetSheetViewProps = {
  diceKey?: DiceKey;
  indexOfLastFacePlaced?: number;
  highlightThisFace?: number;
  sizeModel?: StickerSheetSizeModel;
  transform?: string;
}

export const StickerTargetSheetSvgGroup = observer( (props: StickerTargetSheetViewProps & Bounds) => {
    const {
      diceKey,
      indexOfLastFacePlaced = -1,
      highlightThisFace,
      transform,
    } = props;
    const sizeModel = StickerSheetSizeModel.fromBounds(props);

    return (
      <g {...{transform}}>/* Sticker Sheet */
        <rect
          x={sizeModel.left} y={sizeModel.top}
          width={sizeModel.width} height={sizeModel.height}
          rx={sizeModel.radius} ry={sizeModel.radius}
          stroke={"gray"}
          fill={"white"}
          strokeWidth={sizeModel.linearSizeOfFace / 40}
        />
        {
          (diceKey?.faces ?? EmptyPartialDiceKey).map( (face, index) => (diceKey == null || index > indexOfLastFacePlaced) ? (
            <FaceTargetPlaceholderSvgGroup key={index} linearSizeOfFace={sizeModel.linearSizeOfFace}
              transform={`translate(${
                sizeModel.distanceBetweenDieCenters * (-2 + (index % 5)) }, ${
                sizeModel.distanceBetweenDieCenters * (-2 + Math.floor(index / 5))
              })`}
            />
          ) : (
            <FaceGroupView
              key={index}
              face={face}
              linearSizeOfFace={sizeModel.linearSizeOfFace}
              stroke={"rgba(128, 128, 128, 0.2)"}
              strokeWidth={sizeModel.linearSizeOfFace / 80}
              center={{
                  x: sizeModel.distanceBetweenDieCenters * (-2 + (index % 5)),
                  y: sizeModel.distanceBetweenDieCenters * (-2 + Math.floor(index / 5))}
                }
              highlightThisFace={highlightThisFace === index}
            />
          ))
        }
      </g>
    );
});

export const StickerTargetSheetView = observer( ({maxWidth, maxHeight, ...props}: StickerTargetSheetViewProps & OptionalMaxSizeCalcProps) => (
  <WithBounds aspectRatioWidthOverHeight={portraitSheetWidthOverHeight} {...{maxWidth, maxHeight}}>{ ({bounds}) => {
  const sizeModel = StickerSheetSizeModel.fromBounds(bounds);
  return (
    <svg viewBox={viewBox(bounds)}>
    <StickerTargetSheetSvgGroup {...{...props, ...sizeModel.bounds}} />
    </svg>
  )}}
  </WithBounds>
));


export const Preview_StickerTargetSheetView = () => (
  <StickerTargetSheetView diceKey={DiceKey.testExample} maxHeight="50vh" maxWidth="50vw" indexOfLastFacePlaced={12} />
)