const { MerkleTree, Node } = require('./MerkleTree')

console.log('======== Valid, even')
const data = ['a', 'b', 'c', 'd']
console.log(data)
const leaves = data.map(data => new Node(data))
const tree = new MerkleTree(leaves)

for (let index = 0; index < leaves.length; index++) {
    const element = leaves[index];
    const dataInQuestion = element.data
    const proof = tree.getProof(dataInQuestion)
    console.log(tree.verify(dataInQuestion, proof, tree.getMerkleRoot()))
}
console.log('========')
console.log('======== Valid, odd')
const data2 = ['a', 'b', 'c', 'd', 'e']
console.log(data2)
const leaves2 = data2.map(data => new Node(data))
const tree2 = new MerkleTree(leaves2)

for (let index = 0; index < leaves2.length; index++) {
    const element = leaves2[index];
    const dataInQuestion = element.data
    const proof = tree2.getProof(dataInQuestion)
    console.log(tree2.verify(dataInQuestion, proof, tree2.getMerkleRoot()))
}
console.log('========')

console.log('======== Invalid, bad proof introduced')
const data3 = ['a', 'b', 'c', 'd']
console.log(data3)
const leaves3 = data3.map(data => new Node(data))
const tree3 = new MerkleTree(leaves3)

for (let index = 0; index < leaves3.length; index++) {
    const element = leaves3[index];
    const dataInQuestion = element.data
    const proof = tree3.getProof(dataInQuestion)

    // Bad proof
    proof[0].sibling.data = 'x'

    console.log(tree3.verify(dataInQuestion, proof, tree3.getMerkleRoot()))
}