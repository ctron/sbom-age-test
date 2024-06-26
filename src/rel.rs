use spdx_rs::models::RelationshipType;

#[derive(
    Copy, Clone, Eq, PartialEq, Debug, Hash, strum::IntoStaticStr, strum::Display, strum::EnumIter,
)]
pub enum Relationship {
    Describes,
    Contains,
    DependsOn,
    DevDependsOn,
    Generates,
    PackageOf,
    VariantOf,
    Other,
    NotImplemented,
}

impl Relationship {
    pub fn from_rel(a: String, r#type: &RelationshipType, b: String) -> (String, Self, String) {
        match r#type {
            RelationshipType::Describes => (b, Self::Describes, a),
            RelationshipType::DescribedBy => (a, Self::Describes, b),
            RelationshipType::Contains => (b, Self::Contains, a),
            RelationshipType::ContainedBy => (a, Self::Contains, b),
            RelationshipType::DependsOn => (b, Self::DependsOn, a),
            RelationshipType::DependencyOf => (a, Self::DependsOn, b),
            /*
            RelationshipType::DependencyManifestOf => {}
            RelationshipType::BuildDependencyOf => {}*/
            RelationshipType::DevDependencyOf => (b, Self::DevDependsOn, a),
            /*
            RelationshipType::OptionalDependencyOf => {}
            RelationshipType::ProvidedDependencyOf => {}
            RelationshipType::TestDependencyOf => {}
            RelationshipType::RuntimeDependencyOf => {}
            RelationshipType::ExampleOf => {}
            */
            RelationshipType::Generates => (a, Self::Generates, b),
            /*
            RelationshipType::GeneratedFrom => {}
            RelationshipType::AncestorOf => {}
            RelationshipType::DescendantOf => {}*/
            RelationshipType::VariantOf => (a, Self::VariantOf, b),
            /*
            RelationshipType::DistributionArtifact => {}
            RelationshipType::PatchFor => {}
            RelationshipType::PatchApplied => {}
            RelationshipType::CopyOf => {}
            RelationshipType::FileAdded => {}
            RelationshipType::FileDeleted => {}
            RelationshipType::FileModified => {}
            RelationshipType::ExpandedFromArchive => {}
            RelationshipType::DynamicLink => {}
            RelationshipType::StaticLink => {}
            RelationshipType::DataFileOf => {}
            RelationshipType::TestCaseOf => {}
            RelationshipType::BuildToolOf => {}
            RelationshipType::DevToolOf => {}
            RelationshipType::TestOf => {}
            RelationshipType::TestToolOf => {}
            RelationshipType::DocumentationOf => {}
            RelationshipType::OptionalComponentOf => {}
            RelationshipType::MetafileOf => {}*/
            RelationshipType::PackageOf => (a, Self::PackageOf, b),
            /*
            RelationshipType::Amends => {}
            RelationshipType::PrerequisiteFor => {}
            RelationshipType::HasPrerequisite => {}
            RelationshipType::RequirementDescriptionFor => {}
            RelationshipType::SpecificationFor => {}
             */
            RelationshipType::Other => (a, Self::Other, b),

            n => {
                // panic!("Need to implement: {n:?}");
                log::warn!("Not implemented: {n:?}");
                (a, Self::NotImplemented, b)
            }
        }
    }
}
