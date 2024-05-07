# Testing Apache AGE

The goal is to get a better understanding of SBOMs (SPDX SBOMs) in the context of graph databases. Using Apache AGE.

## Fetching an initial dataset

This needs to be done at least once.

```bash
sbom download https://access.redhat.com/security/data/sbom/beta -k https://access.redhat.com/security/data/97f5eac4.txt#77E79ABE93673533ED09EBE2DCE3823597F5EAC4 -d data/current 
```

## Starting services (PostgreSQL with AGE)

```bash
podman-compose up
```

> [!IMPORTANT]  
> The compose setup exposes Postgres on port 5433 instead of the default port.

## Ingesting data

```bash
cargo run
```

You can use `RUST_LOG=info` to get more info.

> [!IMPORTANT]  
> Re-running the ingesting will drop and re-create the graph instance.

### Ingesting a subset

You can use `-p prefix` or `--prefix prefix` to limit the files ingested. The prefix is checked again the start of
the file name.

### SPDX license expressions

> [!NOTE]  
> The ingesting process will replace all invalid license expressions with `NOASSERTION`. It will also store
> all files with a `.processed` extension to speed up re-running the process.

## Playing with the data

Connect to PostgreSQL and execute the following commands before interactive with the data:

```sql
LOAD 'age';
SET search_path = ag_catalog, "$user", public;
```

Then you can play with the data. See [`test.sql`](test.sql) for some examples.

## Loading a prepared database dump

Download the `dq.sql.xz` file and decompress it and rename it to `db.sql`:

```bash
wget https://sbom.dentrassi.de/age-test/db-20240507.sql.xz
mv db-20240507.sql.xz db.sql.xz
xz -d db.sql.xz
```

The load it into a newly created (empty) Postgres instance:

```bash
psql -h localhost -p 5433 -U postgres -d postgres -f db.sql
psql -h localhost -p 5433 -U postgres -d postgres -f perf.sql
```

## age-viewer

You can inspect the data with the [age-viewer](https://github.com/apache/age-viewer).

> [!NOTE]
> As long as [PR #171] isn't merged, you need to use the fork. Otherwise, you can just clone `https://github.com/apache/age-viewer`.

Get the code:

```bash
git clone https://github.com/ctron/age-viewer -b feature/fix_pg_16_1
cd age-viewer
npm run setup
npm run start
```

Navigate your browser to <http://localhost:3000> and use the following credentials:

* **Host:** `localhost`
* **Port:** `5433`
* **Username:** `postgres`
* **Password:** `postgres`
* **Database:** `postgres`
