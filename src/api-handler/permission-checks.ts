import {
  ApiCalls, Recipe, Exceptions
} from "@dicekeys/dicekeys-api-js";
import { requestRequiresDerivationOptionOfClientMayRetrieveKey } from "@dicekeys/dicekeys-api-js/dist/api-calls";


/**
 * Validate that the client is not receiving a key which operations should be
 * performed in the DiceKeys app without setting "clientMayRetrieveKey": true
 * in the derivation options.
 */
export const throwIfClientMayNotRetrieveKey = (request: ApiCalls.ApiRequestObject) => {
  if (
    requestRequiresDerivationOptionOfClientMayRetrieveKey(request) &&
    !Recipe(request.recipe).clientMayRetrieveKey
  ) {
    throw new Exceptions.ClientMayRetrieveKeyNotSetInRecipe()
  }
}