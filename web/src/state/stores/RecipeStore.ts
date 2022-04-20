import {
  StoredRecipe,
  recipeDefaultBaseName,
  isStoredRecipe,
} from "../../dicekeys/StoredRecipe";
import { action, makeAutoObservable, toJS } from "mobx";
import { jsonStringifyWithSortedFieldOrder } from "../../utilities/json";
import { defaultOnException } from "../../utilities/default-on-exception";
import { typedArrayFilter} from "../../utilities/typing";

// Name of the old recipe store, which was a JSON encoded array
// of JSON encoded strings (unnecessary double JSON encoding)
const DepractedRecipeStoreName = "RecipeStore";

// Name of the current recipe store which is a JSON encoded array
// of StoredRecipe objects.
const RecipeStoreV2Name = "RecipeStoreV2";

const sortStoredRecipes = (recipeArray: StoredRecipe[]): StoredRecipe[] =>
  recipeArray.sort( (a, b): number => {
    const aName = a.name ?? defaultOnException(() => recipeDefaultBaseName(JSON.parse(a.recipeJson))) ?? "";
    const bName = b.name ?? defaultOnException(() => recipeDefaultBaseName(JSON.parse(b.recipeJson))) ?? "";
    return aName != bName ? ((aName < bName) ? -1 : 1) :
      a.type != b.type ? (a.type < b.type ? -1 : 1) :
      a.recipeJson < b.recipeJson ? - 1 : 1
  })

const filterArrayOfStoredRecipes = typedArrayFilter(isStoredRecipe);

// Format was JSON for `{recipeJsonArray: [string]}` where each string was a JSON encoded StoredRecipe
const readDeprecatedRecipeFormat = (): StoredRecipe[] => {
  const storageObject = defaultOnException( () => JSON.parse(window.localStorage.getItem(DepractedRecipeStoreName) || "{}"));
  if (typeof storageObject !== "object" || !("recipeJsonArray" in storageObject)) return [];
  const recipeJsonArray = storageObject.recipeJsonArray;
  if (!Array.isArray(recipeJsonArray)) { return []; }
  const arrayOfJsonParsedStrings = recipeJsonArray.map( (storedRecipeJson: unknown) =>
      (typeof storedRecipeJson !== "string") ? undefined :
        defaultOnException( () => JSON.parse(storedRecipeJson))
  );
  return filterArrayOfStoredRecipes(arrayOfJsonParsedStrings);
}

const readArrayOfStoredRecipes = (): StoredRecipe[] => {
  const recipeStoreJson = window.localStorage.getItem(RecipeStoreV2Name);
  if (recipeStoreJson == null) {
    // We've never used the v2 recipe store.
    // Read from the deprecated store if it's there, which will return an empty array if it's not.
    return readDeprecatedRecipeFormat();
  }
  return filterArrayOfStoredRecipes(defaultOnException(JSON.parse(recipeStoreJson)));
}

const storedRecipeEqual = (a: StoredRecipe, b: StoredRecipe): boolean =>
  a.recipeJson === b.recipeJson && a.type === b.type;

const removeDuplicatesFavorEarlierIndexes = (storedRecipes: StoredRecipe[]): StoredRecipe[] => {
  const duplicateFreeStoredRecipes: StoredRecipe[] = [];
  for (const candidateStoredRecipeToAppend of storedRecipes) {
    const candidateIsNotDuplicate = duplicateFreeStoredRecipes.find(
        x => storedRecipeEqual(x, candidateStoredRecipeToAppend)
    ) != null;
    if (candidateIsNotDuplicate) {
      duplicateFreeStoredRecipes.push(candidateStoredRecipeToAppend);
    }
  }
  return duplicateFreeStoredRecipes;
}

// in local storage as
// RecipeStore = undefined | JSON.stringify({
//  recipeJsonArray: JSON.stringify(StoredRecipe)[]
//})
class RecipeStoreClass {
//  protected recipeJsonArray: string[];
  _storedRecipeCache: StoredRecipe[];

  setStoredRecipes = action ( (newValue: StoredRecipe[]) => {
    this._storedRecipeCache = newValue;
    window.localStorage.setItem(RecipeStoreV2Name, JSON.stringify(toJS(newValue)));
  });

  /** An observable list of StoredRecipes  */
  get storedRecipes(): StoredRecipe[] {
    // We want to always read from local storage on a new call, but also always update
    // on write when the cache changes, so we'll read both and compare to force both to
    // always happen
    const storedRecipeCache = this._storedRecipeCache;
    const storedReipesFromStorage = readArrayOfStoredRecipes();
    // This equality forces mobx to update if ever the cache is changed.
    return sortStoredRecipes(
      (jsonStringifyWithSortedFieldOrder(toJS(storedRecipeCache)) === jsonStringifyWithSortedFieldOrder(storedReipesFromStorage)) ?
        [...storedRecipeCache] : storedReipesFromStorage
    );
  }

  getStoredRecipesJson = (): string => {
    return jsonStringifyWithSortedFieldOrder(toJS(this.storedRecipes));
  }

  addRecipe = (...storedRecipesToAdd: StoredRecipe[]) =>
    this.setStoredRecipes(
      sortStoredRecipes(
        removeDuplicatesFavorEarlierIndexes([...storedRecipesToAdd, ...this._storedRecipeCache])
      )
    )

  importStoredRecipeAsJsonArrary = (storedRecipesAsJsonArray: string) => {
    const recipesToImport = filterArrayOfStoredRecipes(
      defaultOnException( () => JSON.parse(storedRecipesAsJsonArray ))
    );
    this.addRecipe(...recipesToImport);
  }

  removeRecipe = (storedRecipeToRemove: StoredRecipe) =>
    this.setStoredRecipes( this.storedRecipes.filter( sr => !storedRecipeEqual(sr, storedRecipeToRemove)) );

  removeAll = action ( () => {
    this.setStoredRecipes([]);
  });
 
  isRecipeSaved = (candidateStoredRecipe: StoredRecipe): boolean =>
    !!this.storedRecipes.find( savedRecipe => storedRecipeEqual(savedRecipe, candidateStoredRecipe) )

  constructor() {
    this._storedRecipeCache = readArrayOfStoredRecipes();
    makeAutoObservable(this);
  }
}
export const RecipeStore = new RecipeStoreClass();
