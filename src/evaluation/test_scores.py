import networkx as nx
import algorithm_4_hybrid
from pathlib import Path
for g_file in list(Path('output/dataset_test').rglob('*.graphml'))[:25]:
    try:
        G = nx.read_graphml(g_file)
        res = algorithm_4_hybrid.detect(G, None, g_file.stem)
        print(g_file.name, res['risk'], res['rule_score'], res['gat_score'])
    except:
        pass
