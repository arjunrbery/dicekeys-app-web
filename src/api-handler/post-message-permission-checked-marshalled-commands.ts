import {
  DiceKey
} from "../dicekeys/dicekey";
import {
  RequestForUsersConsent,
  UsersConsentResponse,
  Exceptions
} from "@dicekeys/dicekeys-api-js";
import {
  PermissionCheckedMarshalledCommands
} from "./abstract-permission-checked-marshalled-commands"

/**
 * 
 */
export class PostMessagePermissionCheckedMarshalledCommands extends PermissionCheckedMarshalledCommands {
  constructor(
    protected request: MessageEvent,
    loadDiceKeyAsync: () => PromiseLike<DiceKey>,
    requestUsersConsent: (
      requestForUsersConsent: RequestForUsersConsent
    ) => Promise<UsersConsentResponse>,
    private transmitResponse: (response: object) => any = (response: object) => this.defaultTransmitResponse(response)
  ) {
    super(request.origin + "/", loadDiceKeyAsync, requestUsersConsent, false);
  }

  protected unmarshallOptionalStringParameter = (parameterName: string): string | undefined => {
    const value = typeof (this.request?.data) === "object" && this.request?.data[parameterName];
    return (typeof value) === "string" ? value : undefined;
  }
  protected unmarshallBinaryParameter = (parameterName: string): Uint8Array => {
    const value = typeof (this.request?.data) === "object" && this.request?.data[parameterName];
    return ((typeof value) === "object" && (value instanceof Uint8Array)) ?
      value :
      (() => { throw Exceptions.MissingParameter.create(parameterName); })();
  }

  private defaultTransmitResponse = (response: object): any => {
    /**
     * Transmit the response back to the origin it came from
     */
    ( this.request.source as {postMessage: (m: any, origin: string) => unknown})!.postMessage(response, this.request.origin);
  }

  protected sendResponse = (response: [string, string | Uint8Array][]) => {
    const responseObj =
      response.reduce( (responseObj, [name, value]) => {
          responseObj[name] = value;
          return responseObj;
        },
        {} as {[name: string]: string | Uint8Array}
      );
    this.transmitResponse(responseObj)
  }

  static executeIfCommand = (
    loadDiceKeyAsync: () => Promise<DiceKey>,
    requestUsersConsent: (
      requestForUsersConsent: RequestForUsersConsent
    ) => Promise<UsersConsentResponse>,
    messageEvent: MessageEvent
  ) => {
    const command = new PostMessagePermissionCheckedMarshalledCommands(
      messageEvent,
      loadDiceKeyAsync, requestUsersConsent
    );
    if (command.isCommand()) {
      command.execute();
    }    
  }

}
