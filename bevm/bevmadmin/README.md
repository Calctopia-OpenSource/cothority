Navigation: [DEDIS](https://github.com/dedis/doc/tree/master/README.md) ::
[Cothority](../README.md) ::
[Building Blocks](../doc/BuildingBlocks.md) ::
[BEvm](https://github.com/dedis/cothority/blob/main/bevm/README.md) ::
bevmadmin

# bevmadmin - CLI tool to manage BEvm instances

For the details on all the options and arguments, invoke the tool using the `--help` option.

## Creating a new BEvm instance
Assuming ByzCoin config and key files in the current directory (see [bcadmin](https://github.com/dedis/cothority/blob/main/byzcoin/bcadmin/README.md) for details):
```bash
bevmadmin --config . spawn --bc bc-<ByzCoinID>.cfg
```

## Deleting an existing BEvm instance
```bash
bevmadmin --config . delete --bc bc-<ByzCoinID>.cfg --bevmID <BEvm instance ID>
```
