# Writeup for once-unop-a-dijkstar

## Initial Approach

Based on the problem name, description, and the text we get from the remote
server, we figure we need to find the most efficient route from ShippyMcShipFace
to Honolulu given the provided CSV files.

The data is nicely laid out in the CSV files with source, dest, and distance,
so it's pretty easy to build a graph using networkx.  Once we have a graph
built, getting the shortest path from networkx is straightforward:

```python
path = nx.astar_path(g, 'ShippyMcShipFace', 'Honolulu', weight='weight')
```

We also write code to pass our ticket in and submit the path in the format the
remote server expects, which is just the numbers of the intermediate satellites
with no prefix:

```python
def path_to_answer(path: List[str]) -> str:
    answer_list = []
    for name in path:
        if name.startswith('Starlunk'):
            answer_list.append(name[len('Starlunk-'):])
    return ', '.join(answer_list)
```

We get a solution, but the remote server doesn't accept it... we didn't think
it would be that easy.

## Reversing the Binary

We begin to reverse-engineer the binary, looking specifically for things
related to special logic around routing and weighting that would affect our
answer. Several functions' names stood out to us: `determine_target_type`,
`determine_type_weight`, and `get_target_traversal_cost`. So we looked at them
to understand how target nodes are categorized and how weights are applied.

We end up with understanding that `determine_target_type` gets the type based
on the last character in the node name, `determine_type_weight` returns a
factor for weight based on that type, and it is multiplied in
`get_target_traversal_cost`, as summarized below.

```python
custom_weights = [
    2.718,  # STARMANDER
    3.141,  # STARMELEON
    4.04,   # STARZARD
    1999.9, # GATEWAY
]
def get_coeff(name: str) -> float:
    c = name[-1]
    if not c.isdigit():
        v = 3
    else:
        v = int(c) % 3
    return custom_weights[v]
```

As we build the graph we multiply the distance in the CSV by the factor returned
by the function above, adjusting so either the source or dest determines the
factor as necessary.

```python
g = nx.DiGraph()  # initially nx.Graph, but learned later that was wrong
for line in data.split('\n'):
    line = line.strip()
    if not line:
        continue
    source, dest, distance_str = line.split(',')
    # Use dest for factor unless it's ShippyMcShipFace or Honolulu
    if 'Starlunk' not in source:
        distance = get_coeff(source) * float(distance_str)
    else:
        distance = get_coeff(dest) * float(distance_str)
    # Honolulu edges need to be reversed to allow directed traversal
    if source == 'Honolulu':
        g.add_edge(dest, source, weight=float(distance))
    else:
        g.add_edge(source, dest, weight=float(distance))
```

## Almost There

At this point we felt the solution was very close, so we began trying some
variations on what we thought we understood from reversing. Eventually one of
our teammates noticed that there were edges going both directions between
satellites and mentioned looking at the graph as directed rather than
undirected.

Changing the networkx graph class from undirected to directed and handling the
Honolulu edges so that they point to Honolulu as the "dest" resulted in a new
path which satisfied the remote server and popped out the flag.

