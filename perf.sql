
CREATE INDEX edge_start on sboms._ag_label_edge (start_id);
CREATE INDEX edge_end on sboms._ag_label_edge (end_id);

CREATE INDEX "SBOM_id" on sboms."SBOM" (id);
CREATE INDEX "Package_id" on sboms."Package" (id);

CREATE INDEX SBOM__properties ON sboms."SBOM" USING GIN (properties);
CREATE INDEX Package__properties ON sboms."Package" USING GIN (properties);
CREATE INDEX _ag_label__properties ON sboms._ag_label_vertex USING GIN (properties);

CREATE INDEX "Contains_start" on sboms."Contains" (start_id);
CREATE INDEX "Contains_end" on sboms."Contains" (end_id);
CREATE INDEX "PackageOf_start" on sboms."PackageOf" (start_id);
CREATE INDEX "PackageOf_end" on sboms."PackageOf" (end_id);
CREATE INDEX "DevDependsOn_start" on sboms."DevDependsOn" (start_id);
CREATE INDEX "DevDependsOn_end" on sboms."DevDependsOn" (end_id);
CREATE INDEX "DependsOn_start" on sboms."DependsOn" (start_id);
CREATE INDEX "DependsOn_end" on sboms."DependsOn" (end_id);
CREATE INDEX "Describes_start" on sboms."Describes" (start_id);
CREATE INDEX "Describes_end" on sboms."Describes" (end_id);
CREATE INDEX "DescribesDocument_start" on sboms."DescribesDocument" (start_id);
CREATE INDEX "DescribesDocument_end" on sboms."DescribesDocument" (end_id);
CREATE INDEX "Generates_start" on sboms."Generates" (start_id);
CREATE INDEX "Generates_end" on sboms."Generates" (end_id);
CREATE INDEX "NotImplemented_start" on sboms."NotImplemented" (start_id);
CREATE INDEX "NotImplemented_end" on sboms."NotImplemented" (end_id);
CREATE INDEX "Other_start" on sboms."Other" (start_id);
CREATE INDEX "Other_end" on sboms."Other" (end_id);
CREATE INDEX "VariantOf_start" on sboms."Other" (start_id);
CREATE INDEX "VariantOf_end" on sboms."Other" (end_id);

ANALYZE;