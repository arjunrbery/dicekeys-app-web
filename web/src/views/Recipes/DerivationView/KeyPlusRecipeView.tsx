import React from "react";
import { observer } from "mobx-react";
import { RecipeBuilderState } from "../RecipeBuilderState";
import { DiceKey } from "../../../dicekeys/DiceKey";
import { DiceKeyView } from "../../../views/SVG/DiceKeyView";
import { ToggleState } from "../../../state";
import { HoverState } from "../../../state/reusable/HoverState";
import { visibility } from "../../../utilities/visibility";
import { RecipeDescriptionContentView } from "../RecipeDescriptionView";
import { MultilineRecipeJsonView } from "./MultilineRecipeView";
import {
  EditButtonHoverTextView,
  RecipeRibbonButtons,
  RecipeRibbonButtonsView
} from "./RecipeRibbonButtons";
import {
  KeyPlusRecipeColumn
} from "./DerivationViewLayout";
import * as Dimensions from "./DerivationViewLayout";
import styled from "styled-components";

export const PlusSignWidthPercent = 5;
export const PlusSignViewWidth = `${PlusSignWidthPercent}vw` as const;
export const RecipeColumnWidthFormula = `(${Dimensions.ContentWidthInVw}vw - (${Dimensions.DiceKeyBoxSize} + ${PlusSignWidthPercent}vw))` as const;

const BigCaptionOrLabel = styled.span`
  font-family: sans-serif;
  font-size: 3vh;
  flex-direction: row;
  color: ${props => props.theme.colors.foregroundDeemphasized }
`;

const RecipeViewContainer = styled.div`
  display: flex;
  flex-direction:column;
`;


const RecipeRoundedRectRadiusAndPadding = `0.35rem`;
const RecipeColumnWidthWithinPaddingFormula = `(${RecipeColumnWidthFormula} - (2  * (${RecipeRoundedRectRadiusAndPadding})))` as const;

const RecipeViewRoundedRect = styled.div`
  display: flex;
  flex-direction: column;
  justify-content: space-around;
  align-items: flex-start;
  padding: ${RecipeRoundedRectRadiusAndPadding};
  width: calc(${RecipeColumnWidthWithinPaddingFormula});
  min-height: calc(${Dimensions.DiceKeyBoxSize} - 2 * (${RecipeRoundedRectRadiusAndPadding}));
  border-radius: ${RecipeRoundedRectRadiusAndPadding};
  background-color: rgba(128,128,196,0.10);
  color: ${ props => props.theme.colors.foreground }
`;

const InteriorLabelForRecipe = styled(BigCaptionOrLabel)`
  margin-left: 1rem;
`;

const RecipeSeparator = styled.div`
  margin-top: 0.25vh;
  margin-bottom: 0.25vh;
  width: calc(${RecipeColumnWidthWithinPaddingFormula} - 0.7rem);
  border-bottom: 1px solid rgba(0,0,0,0.1);
`;

const RecipeView = observer( ({recipeBuilderState, editButtonsHoverState}: {
  recipeBuilderState: RecipeBuilderState,
  editButtonsHoverState: HoverState<RecipeRibbonButtons>
}) => (
  <RecipeViewContainer>
    <RecipeRibbonButtonsView {...{recipeBuilderState, editButtonsHoverState}} />
    <RecipeViewRoundedRect>
      { !recipeBuilderState.recipeIsNotEmpty ? (
        <InteriorLabelForRecipe>Recipe</InteriorLabelForRecipe>
      ) : (<>
          <MultilineRecipeJsonView recipeJson={ recipeBuilderState.canonicalRecipeJson  }/>
          <RecipeSeparator/>
          <div>
            <RecipeDescriptionContentView state={recipeBuilderState} />
          </div>  
        </>)
      }
    </RecipeViewRoundedRect>
  </RecipeViewContainer>
));

const KeyPlusRecipeRow = styled.div`
  display: flex;
  flex-direction: row;
  justify-content: flex-start;
  align-items: center;
`;

const RowElement = styled.div`
  display: flex;
  flex-direction: column;
  align-items: center;
  align-content: center;
  justify-content: center;
`;

const ElementInDiceKeyColumn = styled(RowElement)`
  width: calc(${Dimensions.DiceKeyBoxSize});
  height: auto;
`;

const ElementInPlusSignColumn = styled(RowElement)`
  width: calc(${PlusSignViewWidth});
  font-size: ${Dimensions.DownArrowAndPlusSignViewHeight}vh;
`;

const ElementInRecipeColumn = styled(RowElement)`
  width: calc(${RecipeColumnWidthFormula});
`;

export const KeyPlusRecipeView = observer ( ( {diceKey, recipeBuilderState}: {
  diceKey: DiceKey,
  recipeBuilderState: RecipeBuilderState
}) => {
  const editButtonsHoverState = new HoverState<RecipeRibbonButtons>();
  return (
  <KeyPlusRecipeColumn>
    <EditButtonHoverTextView {...{editButtonsHoverState, recipeBuilderState}}/>
    <KeyPlusRecipeRow>
      {/* Key */}
      <ElementInDiceKeyColumn>
        <DiceKeyView faces={diceKey.faces} size={`min(${Dimensions.DiceKeyBoxMaxHeight},${Dimensions.DiceKeyBoxMaxWidth})`}
          obscureAllButCenterDie={ToggleState.ObscureDiceKey}
        />
      </ElementInDiceKeyColumn>
      {/* Plus sign */}
      <ElementInPlusSignColumn>+</ElementInPlusSignColumn>
      {/* Recipe */}
      <ElementInRecipeColumn>
        <RecipeView {...{recipeBuilderState, editButtonsHoverState}} />
      </ElementInRecipeColumn>
    </KeyPlusRecipeRow>
    <KeyPlusRecipeRow>
      {/* Key caption */}
      <ElementInDiceKeyColumn>
        <BigCaptionOrLabel>
          Key
        </BigCaptionOrLabel>
      </ElementInDiceKeyColumn>
      {/* Down arrow as HTML entity &#8659; */}
      <ElementInPlusSignColumn>
        <span style={{
          /* Adjust arrow placement so that it doesn't overflow bottom */
          marginTop: `-${0.15 * Dimensions.DownArrowAndPlusSignViewHeight}vh`,
        }}>&#8659;
        </span>
      </ElementInPlusSignColumn>
      {/* Recipe label (hidden if there's no recipe and label is inside recipe box) */}
      <ElementInRecipeColumn>
        <BigCaptionOrLabel style={visibility(recipeBuilderState.recipeIsNotEmpty)}>
          Recipe
        </BigCaptionOrLabel>
      </ElementInRecipeColumn>
    </KeyPlusRecipeRow>
  </KeyPlusRecipeColumn>
)});
