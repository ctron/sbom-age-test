# Testing Apache AGE

## Fetch an initial dataset

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

## Playing with the data

Connect to PostgreSQL and execute the following commands before interactive with the data:

```sql
LOAD 'age';
SET search_path = ag_catalog, "$user", public;
```

Then you can play with the data. See [`test.sql`](test.sql) for some examples.
