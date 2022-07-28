from typing import List
import networkx as nx
from pwn import *


def read_csv(filename: str) -> str:
    data = ''
    with open(filename, 'r') as f:
        for i, line in enumerate(f.readlines()):
            # Skip headers
            if i == 0:
                continue
            data += line
    return data


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


def get_path_weight(path: List[str], g: nx.DiGraph) -> float:
    w = 0
    for i in range(1, len(path)):
        weight_str = g[path[i-1]][path[i]]['weight']
        w += float(weight_str)
    return w


def path_to_answer(p: List[str]) -> str:
    answer_list = []
    for i in p:
        if i.startswith('Starlunk'):
            answer_list.append(i[len('Starlunk-'):])
    return ', '.join(answer_list)


def get_flag(answer):
    host = 'once_unop_a_dijkstar.satellitesabove.me'
    port = 5300

    io = connect(host, port)
    ticket = b"ticket{bravo104979golf3:GBGB-zyjxvPjbwWxVY5pq0IrHGkGF-ViR9db4Mdt6PNaInF2qrHHIYLk9ARS73UYXQ}"
    io.sendline(ticket)

    prompt = io.recvuntil(b"Your answer:")

    io.sendline(answer.encode())
    print(io.recvall(timeout=1.0).decode().strip())

    io.close()


if __name__ == '__main__':
    print('Reading data...')
    data = ''
    for csv_file in ['gateways.csv', 'sats.csv', 'users.csv']:
        data += read_csv(csv_file)

    g = nx.DiGraph()

    print('Building directed graph...')
    for line in data.split('\n'):
        line = line.strip()
        if not line:
            continue
        source, dest, distance_str = line.split(',')
        if 'Starlunk' not in source:
            distance = get_coeff(source) * float(distance_str)
        else:
            distance = get_coeff(dest) * float(distance_str)
        # Honolulu edges need to be reversed to allow directed traversal
        if source == 'Honolulu':
            g.add_edge(dest, source, weight=float(distance))
        else:
            g.add_edge(source, dest, weight=float(distance))

    print('Finding path...')
    p = nx.astar_path(g, 'ShippyMcShipFace', 'Honolulu', weight='weight')

    print(f'path={p}')
    #print(f'weight={get_path_weight(p, g)}')

    answer = path_to_answer(p)
    print(f'{answer=}')

    get_flag(answer)
