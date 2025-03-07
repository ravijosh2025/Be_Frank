FactoryBot.define do
  factory :user do
    first_name { Faker::Name.first_name }
    last_name { Faker::Name.last_name }
    role { %w[user admin].sample } # Randomly assigns either "user" or "admin"
    mobile_number { Faker::Number.number(digits: 10).to_s }
    email { Faker::Internet.unique.email }
    password { "password123" }
    password_confirmation { "password123" }
    address { Faker::Address.city }
  end
end
