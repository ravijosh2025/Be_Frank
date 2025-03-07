FactoryBot.define do
  factory :school do
    name { Faker::Educator.secondary_school }
    city { Faker::Address.city }
    state { Faker::Address.state }
  end
end
