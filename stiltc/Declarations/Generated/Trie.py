class Trie(object):
    def __init__(self, char='*'):
        self.char = char
        self.children = []
        self.word_finished = False

    def add(root, word):
        node = root
        for char in word:

            # Find the current character in the current node
            node_found = False
            for child in node.children:
                if child.char == char:
                    node = child
                    node_found = True
                    break

            # Add a new chlid
            if not node_found:
                child = Trie(char)
                node.children.append(child)
                node = child

        node.word_finished = True

    def serialize(root, dmp=[]):
        first = not dmp
        dmp.append([root.char, len(root.children), root.word_finished])
        for c in root.children:
            c.serialize(dmp)

        return dmp if not first else dmp[1:]

    def query(root, query):
        """
        Returns: 
        is_keyword, can_continue
        """

        # Empty
        if not root or not root.children:
            return False, False

        # Traverse the trie
        node = root
        for char in query:

            # Look a child with the current char.
            # Match the char and traverse to the node.
            char_found = False
            for child in node.children:
                if child.char == char:
                    char_found = True
                    node = child
                    break

            # No matches for a char in the query.
            # The search has failed.
            if not char_found:
                return False, False

        return node.word_finished, True if node.children else False


if __name__ == "__main__":
    trie = Trie('*')
    trie.add('hacker')
    trie.add('hackathon')
    trie.add('hack')
    trie.add('hackamogus')

    print(trie.query('hac'))
    print(trie.query('hack'))
    print(trie.query('hackathon'))
    print(trie.query('ha'))
    print(trie.query('hammer'))
    print(trie.query('hacka'))

    print(trie.serialize())
