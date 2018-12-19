const crypto = require('crypto')

class MerkleTree {
    constructor(nodes) {
        this.nodes = nodes
        this.layers = []
        this.generateTree()
    }

    /**
     * Tree generation.
     * 
     * @example
     * 
     *     [5]
     *   [4] [3]
     * [1] [2] [3]
     * 
     * Node length: 3
     * Target layer number: Math.ceiling(3 / 2) + 1 = 3
     * Node at index 2 is a lonely leaf so it will get carried over until (targetLayerNumber - 1)
     * 
     *     [  7  ]
     *   [5]     [6]
     * [1] [2] [3] [4]
     * 
     * Node length: 4
     * Target layer number: Math.ceiling(4 / 2) + 1 = 3
     * There is no lonely leaf so all nodes will be processed evenly
     */
    generateTree() {
        let leavesCopy = Array.from(this.nodes)
        let lonelyLeaf

        this.layers.push(leavesCopy)
        let targetLayerNumber = Math.ceil(this.nodes.length / 2) + 1

        while (this.layers.length < targetLayerNumber) {
            const newLayer = []

            for (let iterator = 0; iterator < leavesCopy.length; iterator += 2) {
                const left = leavesCopy[iterator]
                const right = leavesCopy[iterator + 1]

                /**
                 * Nodes are odd, carry over the node with no sibling
                 * to the next layers until an even layer is reached.
                 */
                if (!right) {
                    newLayer.push(left)
                    continue
                }

                const leftRight = [left.hash, right.hash]
                const leaf = new Node(Buffer.concat(leftRight))
                newLayer.push(leaf)
            }

            this.layers.push(newLayer)
            leavesCopy = newLayer
        }

        return this.layers
    }

    /**
     * Retrieves the proof, an array of hashes with position information, 
     * necessary to verify a given single data.
     * 
     * @param {string} rawData 
     */
    getProof(rawData) {
        const proof = []
        const data = new Node(rawData)
        let positionIndex = -1

        /**
         * Linear search for the index of the data where proof is requested
         */
        for (let index = 0; index < this.nodes.length; index++) {
            const element = this.nodes[index];
            if (element.hash.toString('hex') === data.hash.toString('hex')) {
                positionIndex = index
                break
            }
        }

        if (positionIndex === -1) {
            throw new Error('Element not found: ' + rawData)
        }

        /**
         * Get proof path by finding the siblings.
         * 
         * Position information is important so that when we verify the proof,
         * we'll know whether the proof hash should come
         * before or after during concatenation.
         * 
         * Example:
         * Hash: 'aaa'
         * Sibling: {position: left, hash: 000}
         * Output: '000aaa'
         */
        for (let index = 0; index < this.layers.length - 1; index++) {
            let hashPositionIndicator, sibling

            const layer = this.layers[index];
            const position = positionIndex % 2 === 0 ? 'left' : 'right'

            /**
             * If the position of this node is on the left,
             * the sibling is on the right, and vice-versa.
             */
            if (position === 'left') {
                hashPositionIndicator = 'right'
                sibling = positionIndex + 1
            } else {
                hashPositionIndicator = 'left'
                sibling = positionIndex - 1
            }

            proof.push({
                hashPositionIndicator,
                sibling: layer[sibling]
            })
            
            /**
             * Move one layer up.
             * 
             * Example:
             * 
             * [1] [2] [3] [4]
             * 
             * Chosen element is [3] at index [2]
             * nextPositionIndex = currentPositionIndex / 2
             *                   = [2] / 2
             * nextPositionIndex = [1]
             * 
             * Adding the next layer:
             * 
             *   [5]     [6]
             * [1] [2] [3] [4]
             * 
             * nextPositionIndex = [1], entry: [6]
             * 
             * And so on...
             */
            positionIndex = (positionIndex / 2)

            if (!Number.isInteger(positionIndex)) {
                positionIndex = Math.ceil(positionIndex) - 1
            }
        }

        return proof
    }

    /**
     * Get the topmost layer as it is equivalent to the merkle root.
     */
    getMerkleRoot() {
        return this.layers[this.layers.length - 1][0].hash.toString('hex')
    }

    /**
     * Fancy console printing stuff.
     */
    print() {
        for (let iterator = this.layers.length - 1; iterator >= 0; iterator--) {
            const layer = this.layers[iterator]

            for (let index = 0; index < layer.length; index++) {
                const element = layer[index];
                console.log('|' + new Array(this.layers.length - iterator).fill('-').join(''), element.hash.toString('hex'))
            }
        }
    }

    /**
     * Verify that the given raw data and supplied proof
     * will lead to the same merkle root.
     * 
     * @example
     * 
     *           [  i  ]
     *     [  h  ]     [e]
     *   [f]     [g]   [e] 
     * [a] [b] [c] [d] [e]
     *
     * If we are going to verify the existence of entry [c],
     * we will only need the following data (c,d,f,e):
     * 
     *           [  x  ]
     *     [  x  ]     [e]
     *   [f]     [x]   [ ] 
     * [ ] [ ] [c] [d] [ ]
     * 
     * From this, we can derive entries marked as [x] given
     * the sibling data from the previous layers.
     *  
     * @param {string} rawData 
     * @param {Array<Object>} proof 
     * @param {string} merkleRoot 
     */
    verify(rawData, proof, merkleRoot) {
        let data = new Node(rawData)

        for (let index = 0; index < proof.length; index++) {
            const element = proof[index]
            const sibling = element.sibling
            const position = element.hashPositionIndicator

            let concat

            if (position === 'left') {
                concat = [sibling.hash, data.hash]
            } else {
                if (!sibling) {
                    /**
                     * This element is a lonely leaf, no siblings to concatenate
                     * so move on.
                     */
                    continue
                } else {
                    concat = [data.hash, sibling.hash]
                }
            }

            const nextLayerHash = new Node(Buffer.concat(concat))
            data = nextLayerHash
        }

        return data.hash.toString('hex') === merkleRoot
    }
}

/**
 * Encapsulation of the merkle tree's data implementation
 * so that hash implementation can be changed in one place.
 */
class Node {
    constructor(data) {
        this.data = data
    }

    get hash() {
        return crypto.createHash('SHA256').update(this.data).digest()
    }
}

module.exports = { MerkleTree, Node }