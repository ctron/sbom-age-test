use crate::rel::Relationship;
use apache_age::tokio::{AgeClient, Client};
use apache_age::AgType;
use serde_json::json;
use spdx_rs::models::SPDX;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::ops::Deref;
use tokio_postgres::{NoTls, Statement};

const GRAPH: &str = "sboms";

pub struct Database {
    client: Client,
}

impl Deref for Database {
    type Target = Client;

    fn deref(&self) -> &Self::Target {
        &self.client
    }
}

impl Database {
    pub async fn new(config: &str) -> anyhow::Result<Self> {
        let (mut client, connection) = Client::connect_age(config, NoTls).await?;

        tokio::spawn(async move {
            if let Err(e) = connection.await {
                eprintln!("connection error: {}", e);
            }
        });

        if client.graph_exists(GRAPH).await? {
            client.drop_graph(GRAPH).await?;
        }

        client.create_graph(GRAPH).await?;

        // create to initial labels

        for label in ["SBOM", "Package"] {
            client
                .execute_cypher::<()>(GRAPH, r#"CREATE(:{label})"#, None)
                .await?;
            client
                .execute_cypher::<()>(GRAPH, r#"MATCH (v:{label}) DELETE v"#, None)
                .await?;
        }

        // create indexes

        client
            .execute(
                r#"
CREATE UNIQUE INDEX "SBOM__id_namespace" ON sboms."SBOM" (agtype_access_operator(properties, '"id"'), agtype_access_operator(properties, '"namespace"'))
        "#,
                &[],
            )
            .await?;
        client
            .execute(
                r#"
CREATE UNIQUE INDEX "Package__id_namespace" ON sboms."Package" (agtype_access_operator(properties, '"id"'), agtype_access_operator(properties, '"namespace"'))
        "#,
                &[],
            )
            .await?;

        // done

        Ok(Self { client })
    }

    pub async fn ingest(&mut self, sbom: SPDX) -> anyhow::Result<()> {
        log::info!(
            "Ingest - packages: {}, relationships: {}",
            sbom.package_information.len(),
            sbom.relationships.len()
        );

        // add SBOM itself

        self.client
            .execute_cypher(
                GRAPH,
                r#"
CREATE(:SBOM {id: $id, name: $name, namespace: $namespace})
"#,
                Some(AgType(Sbom {
                    id: sbom.document_creation_information.spdx_identifier.clone(),
                    namespace: sbom
                        .document_creation_information
                        .spdx_document_namespace
                        .clone(),
                    name: sbom.document_creation_information.document_name.clone(),
                })),
            )
            .await?;

        // add packages

        let add_package = self
            .client
            .prepare_cypher(
                GRAPH,
                r#"
CREATE(:Package {id: $id, namespace: $namespace, name: $name, purls: $purls, cpes: $cpes})
"#,
                true,
            )
            .await?;

        for package in &sbom.package_information {
            let mut purls = vec![];
            let mut cpes = vec![];
            for r in &package.external_reference {
                match &*r.reference_type {
                    "purl" => purls.push(r.reference_locator.clone()),
                    "cpe22Type" => cpes.push(r.reference_locator.clone()),
                    _ => {}
                }
            }

            self.client
                .query(
                    &add_package,
                    &[&AgType(Package {
                        id: package.package_spdx_identifier.clone(),
                        name: package.package_name.clone(),
                        namespace: sbom
                            .document_creation_information
                            .spdx_document_namespace
                            .clone(),
                        cpes,
                        purls,
                    })],
                )
                .await?;
        }

        // add "document describes"

        for id in &sbom.document_creation_information.document_describes {
            self.client
                .execute_cypher(
                    GRAPH,
                    r#"
MATCH (a), (b)
WHERE a.id = $a AND a.namespace = $namespace AND b.id = $b AND b.namespace = $namespace
CREATE (a)-[:DescribesDocument]->(b)
"#,
                    Some(AgType(json!({
                        "a": id,
                        "b": sbom.document_creation_information.spdx_identifier.clone(),
                        "namespace": sbom
                            .document_creation_information
                            .spdx_document_namespace
                            .clone(),
                    }))),
                )
                .await?;
        }

        // add relationships

        let mut prep = HashMap::<_, Statement>::new();

        for rel in &sbom.relationships {
            let (left, rel, right) = Relationship::from_rel(
                rel.spdx_element_id.clone(),
                &rel.relationship_type,
                rel.related_spdx_element.clone(),
            );

            let stmt = match prep.entry(rel) {
                Entry::Occupied(entry) => entry.get().clone(),
                Entry::Vacant(entry) => {
                    let stmt = self
                        .client
                        .prepare_cypher(
                            GRAPH,
                            &format!(
                                r#"
    MATCH (a), (b)
    WHERE a.id = $a AND a.namespace = $namespace AND b.id = $b AND b.namespace = $namespace
    CREATE (a)-[:{type}]->(b)
"#,
                                type = rel
                            ),
                            true,
                        )
                        .await?;
                    entry.insert(stmt).clone()
                }
            };

            self.client
                .query(
                    &stmt,
                    &[&AgType(Relation {
                        namespace: sbom
                            .document_creation_information
                            .spdx_document_namespace
                            .clone(),
                        a: left,
                        b: right,
                    })],
                )
                .await?;
        }

        Ok(())
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct Sbom {
    pub id: String,
    pub namespace: String,
    pub name: String,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct Package {
    pub id: String,
    pub namespace: String,
    pub name: String,
    pub purls: Vec<String>,
    pub cpes: Vec<String>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct Relation {
    pub namespace: String,
    pub a: String,
    pub b: String,
}
