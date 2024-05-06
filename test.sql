-- init

LOAD 'age';
SET search_path = ag_catalog, "$user", public;

-- create a new graph

SELECT create_graph('sboms');

-- clean up

SELECT drop_graph('sboms', true);

-- create a new sbom

SELECT *
FROM cypher('sboms', $$
    CREATE (:SBOM {name: 'sbom1'})
$$) as (v agtype);

SELECT *
FROM cypher('sboms', $$
    CREATE (:Package {name: 'package1'})
$$) as (v agtype);

SELECT *
FROM cypher('sboms', $$
    MATCH (a:SBOM), (b:Package)
    WHERE a.name = 'sbom1' AND b.name = 'package1'
    CREATE (a)-[e:describes]->(b)
    RETURN e
$$) as (v agtype);

SELECT *
FROM cypher('sboms', $$
    CREATE (:Package {name: 'package2'})
$$) as (v agtype);

SELECT *
FROM cypher('sboms', $$
    MATCH (a:SBOM), (b:Package)
    WHERE a.name = 'sbom1' AND b.name = 'package2'
    CREATE (a)-[e:describes]->(b)
    RETURN e
$$) as (v agtype);

-- now play

-- return all

SELECT *
FROM cypher('sboms', $$
    MATCH(v)
    RETURN v
$$) as (a agtype);

SELECT *
FROM cypher('sboms', $$
    MATCH(v:SBOM {name: 'DIRSRV-12.1-RHEL-9'})
    RETURN v
$$) as (a agtype);

SELECT *
FROM cypher('sboms', $$
    MATCH(v:Package)
    RETURN v
$$) as (a agtype);

SELECT *
FROM cypher('sboms', $$
    MATCH(v:SBOM)
    RETURN v
$$) as (a agtype);

-- return related

SELECT *
FROM cypher('sboms', $$
    MATCH (a:SBOM {name: 'DIRSRV-12.1-RHEL-9'})-[r]-(b)
    RETURN a.name, a.namespace, label(r), b.id
$$) as (a agtype, b agtype, c agtype, d agtype);

SELECT *
FROM cypher('sboms', $$
    MATCH (a {id: 'SPDXRef-5aa79381-54ea-42dc-b27f-5200855ec839', namespace: 'https://access.redhat.com/security/data/sbom/spdx/DIRSRV-12.1-RHEL-9'})-[r]-(b)
    RETURN a.name, label(r), b.id, b.name
$$) as (a agtype, b agtype, c agtype, d agtype);

SELECT *
FROM cypher('sboms', $$
    MATCH (a {id: 'SPDXRef-5aa79381-54ea-42dc-b27f-5200855ec839', namespace: 'https://access.redhat.com/security/data/sbom/spdx/DIRSRV-12.1-RHEL-9'})-->(b)
    RETURN a, b
$$) as (a agtype, b agtype);

SELECT *
FROM cypher('sboms', $$
    MATCH(a:Package {name: 'DIRSRV-12.1-RHEL-9'})-->(b:Package)
    RETURN a, b
$$) as (a agtype, b agtype);

-- return edges

SELECT *
FROM cypher('sboms', $$
    MATCH(a) -[r]-> (b)
    RETURN a.name, r, b.name
$$) as (a agtype, b agtype, c agtype);

SELECT *
FROM cypher('sboms', $$
    MATCH(a:Package {name: 'python39'})-[*]->(b)
    RETURN a, b
$$) as (a agtype, b agtype);

-- select what describes an SBOM

SELECT *
FROM cypher('sboms', $$
    MATCH(a:SBOM )-[r]-(b)
    RETURN a.name, a.namespace, type(r), b.name, b.cpes
$$) as (a agtype, b agtype, c agtype, d agtype, e agtype);

SELECT *
FROM cypher('sboms', $$
    MATCH(a:SBOM )-[*]->()-[r]->(b:Package)
    RETURN a.name, type(r), b.name, b.purls
$$) as (a agtype, b agtype, c agtype, d agtype);

-- all relationships of the SBOM

SELECT *
FROM cypher('sboms', $$
    MATCH(a:SBOM {namespace: 'https://access.redhat.com/security/data/sbom/spdx/DIRSRV-12.1-RHEL-9'} )-[r]->(b)
    RETURN a.name, labels(a), type(r), b.name, labels(b), b.cpes
$$) as (a agtype, b agtype, c agtype, d agtype, e agtype, f agtype);

-- first level

SELECT *
FROM cypher('sboms', $$
    MATCH p = (a:SBOM {namespace: 'https://access.redhat.com/security/data/sbom/spdx/DIRSRV-12.1-RHEL-9'} )-[*]-()-[r]-(b)
    RETURN a.name, labels(a), relationships(p), type(r), b.name, labels(b), b.purls
$$) as (a agtype, b agtype, c agtype, d agtype, e agtype, f agtype, g agtype);

SELECT *
FROM cypher('sboms', $$
    MATCH(a:Package {namespace: 'https://access.redhat.com/security/data/sbom/spdx/DIRSRV-12.1-RHEL-9'} )-[r]->(b)
    RETURN a.name, labels(a), type(r), b.name, labels(b)
$$) as (a agtype, b agtype, c agtype, d agtype, e agtype);

SELECT *
FROM cypher('sboms', $$
    MATCH(a:Package {namespace: 'https://access.redhat.com/security/data/sbom/spdx/DIRSRV-12.1-RHEL-9'})
    RETURN a.name, a
$$) as (a agtype, b agtype);
