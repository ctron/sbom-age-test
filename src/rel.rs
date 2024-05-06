use spdx_rs::models::RelationshipType;

#[derive(Copy, Clone, Eq, PartialEq, Debug, Hash, strum::IntoStaticStr, strum::Display)]
pub enum Relationship {
    Describes,
    Contains,
    DependsOn,
    PackageOf,
}

impl Relationship {
    pub fn from_rel(a: String, r#type: &RelationshipType, b: String) -> (String, Self, String) {
        match r#type {
            RelationshipType::Describes => (a, Self::Describes, b),
            RelationshipType::DescribedBy => (b, Self::Describes, a),
            RelationshipType::Contains => (a, Self::Contains, b),
            RelationshipType::ContainedBy => (b, Self::Contains, a),
            RelationshipType::DependsOn => (a, Self::DependsOn, b),
            RelationshipType::DependencyOf => (b, Self::DependsOn, a),
            /*
            RelationshipType::DependencyManifestOf => {}
            RelationshipType::BuildDependencyOf => {}
            RelationshipType::DevDependencyOf => {}
            RelationshipType::OptionalDependencyOf => {}
            RelationshipType::ProvidedDependencyOf => {}
            RelationshipType::TestDependencyOf => {}
            RelationshipType::RuntimeDependencyOf => {}
            RelationshipType::ExampleOf => {}
            RelationshipType::Generates => {}
            RelationshipType::GeneratedFrom => {}
            RelationshipType::AncestorOf => {}
            RelationshipType::DescendantOf => {}
            RelationshipType::VariantOf => {}
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
            RelationshipType::Other => {}
             */
            n => {
                panic!("Need to implement: {n:?}");
            }
        }
    }
}
