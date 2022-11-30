import { assertArgument } from "../utils/index.js";

import { Network } from "./network.js";
import { JsonRpcProvider } from "./provider-jsonrpc.js";

import type { Networkish } from "./network.js";

/**
 *  Aboud Cloudflare...
 *
 *  @_docloc: api/providers/thirdparty
 */
export class CloudflareProvider extends JsonRpcProvider {
    constructor(_network?: Networkish) {
        if (_network == null) { _network = "mainnet"; }
        const network = Network.from(_network);
        assertArgument(network.name === "mainnet", "unsupported network", "network", _network);
        super("https:/\/cloudflare-eth.com/", network, { staticNetwork: network });
    }
}
