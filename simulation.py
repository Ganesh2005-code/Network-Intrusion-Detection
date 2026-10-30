import networkx as nx
import matplotlib.pyplot as plt

# Create Graph
G = nx.Graph()

nodes = ["A","B","C","D","E","F","G","H"]
G.add_nodes_from(nodes)

edges = [
    ("A","B"),
    ("A","C"),
    ("B","D"),
    ("C","D"),
    ("D","E"),
    ("E","F"),
    ("E","H"),
    ("F","G"),
    ("H","G")
]

G.add_edges_from(edges)

# Initial infected node
infected = {"C"}

# Node positions
pos = nx.spring_layout(G, seed=42)

plt.figure(figsize=(8,6))

for step in range(5):

    plt.clf()

    colors = []

    for node in G.nodes():

        if node in infected:
            colors.append("red")
        else:
            colors.append("green")

    nx.draw(
        G,
        pos,
        with_labels=True,
        node_color=colors,
        node_size=1000,
        font_size=12,
        font_weight="bold"
    )

    plt.title(f"Self Replication - Step {step}")

    plt.pause(1)

    new_infected = set(infected)

    for node in infected:
        for neighbor in G.neighbors(node):
            new_infected.add(neighbor)

    infected = new_infected

plt.show()