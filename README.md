# Story-Geth

Golang execution layer implementation of the Story.

[![Discord](https://img.shields.io/badge/discord-join%20chat-blue.svg)](https://discord.gg/StoryProtocol )

Binary archives are published at [https://github.com/piplabs/story-geth/releases](https://github.com/piplabs/story-geth/releases).

## Building `story-geth`

Go version: 1.22.0

```shell
go build -v ./cmd/geth
mv ./geth $HOME/go/bin/story-geth
source $HOME/.bashrc
story-geth version
```

## Running `story-geth`

You can run the mainnet with `--story` flag attached. Here's an example command:

```shell
story-geth --story --datadir="/story/geth/" --verbosity="3" --http --http.corsdomain="*" --http.vhosts="*" --http.addr=127.0.0.1 --http.port="8545" --http.api=web3,debug,eth,txpool --ws --ws.addr=127.0.0.1 --ws.port="8546" --ws.origins="*" --ws.api=debug,eth,txpool --syncmode=full --maxpeers=100
```

### Hardware Requirements

Minimum:

* CPU with 4 cores
* 16GB RAM
* 200GB free storage space to sync the Mainnet
* 25 MBit/sec download Internet service

Recommended:

* Fast CPU with 4+ cores
* 16GB+ RAM
* High-performance SSD with at least 1TB of free space
* 25+ MBit/sec download Internet service

### A Full node on the Iliad test network

Transitioning towards developers, if you'd like to play around with creating Story
contracts, you almost certainly would like to do that without any real money involved until
you get the hang of the entire system. In other words, instead of attaching to the main
network, you want to join the **test** network with your node, which is fully equivalent to
the main network, but with play-IP only.

```shell
story-geth --iliad --syncmode full
```

The `console` subcommand has the same meaning as above and is equally
useful on the testnet too.

Specifying the `--iliad` flag, however, will reconfigure your `story-geth` instance a bit:

* Instead of connecting to the main Story network, the client will connect to the Iliad
   test network, which uses different P2P bootnodes, different network IDs and genesis
   states.
* Instead of using the default data directory (`~/.story` on Linux for example), `story`
   will nest itself one level deeper into a `story` subfolder (`~/.story/iliad` on
   Linux). Note, on OSX and Linux this also means that attaching to a running testnet node
   requires the use of a custom endpoint since `geth attach` will try to attach to a
   production node endpoint by default, e.g., `geth attach <datadir>/geth.ipc`.

  This will connect you to the IPC server from which you can run some helpful queries:
  * `eth.blockNumber` will print out the latest block story-geth is sync’d to - if this is `undefined` there is likely a peer connection or syncing issue
  * `admin.peers` will print out a list of other `story-geth` nodes your client is connected to - if this is blank there is a peer connectivity issue
  * `eth.syncing` will return `true` if story-geth is in the process of syncing, `false` otherwise

*Note: Although some internal protective measures prevent transactions from
crossing over between the main network and test network, you should always
use separate accounts for play and real money. Unless you manually move
accounts, `story-geth` will by default correctly separate the two networks and will not make any
accounts available between them.*

## Contribution

Thank you for considering helping out with the source code! We welcome contributions
from anyone on the internet, and are grateful for even the smallest of fixes!

If you'd like to contribute to story-geth, please fork, fix, commit and send a pull request
for the maintainers to review and merge into the main code base. If you wish to submit
more complex changes though, please check up with the core devs first on [our Discord Server](https://discord.gg/StoryProtocol)
to ensure those changes are in line with the general philosophy of the project and/or get
some early feedback which can make both your efforts much lighter as well as our review
and merge procedures quick and simple.

Please see the [Story Network Guide](https://docs.story.foundation/docs/story-network#/) for more details on configuring your environment, managing project dependencies, and testing procedures.

## Security

We welcome responsible disclosure of vulnerabilities. Please see our [security policy](SECURITY.md) for more information.

## License

The story-geth library (i.e. all code outside of the `cmd` directory) is licensed under the
[GNU Lesser General Public License v3.0](https://www.gnu.org/licenses/lgpl-3.0.en.html),
also included in our repository in the `COPYING.LESSER` file.

The story-geth binaries (i.e. all code inside of the `cmd` directory) are licensed under the
[GNU General Public License v3.0](https://www.gnu.org/licenses/gpl-3.0.en.html), also
included in our repository in the `COPYING` file.

## Local Development with Story-Localnet

To simplify local development and testing, developers can use the **Story-Localnet** project, which allows multiple Story nodes to run locally using Docker. This setup facilitates easy testing and experimentation.

Find more information and setup instructions here:
[Story-Localnet GitHub Repository](https://github.com/piplabs/story-localnet).
