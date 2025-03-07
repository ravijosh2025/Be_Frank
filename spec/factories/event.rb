FactoryBot.define do
  factory :event do
    name { Faker::Lorem.sentence(word_count: 3) }
    description { Faker::Lorem.paragraph(sentence_count: 2) }
    date { Faker::Date.forward(days: 30) }
    user
    school

    # Attach a test image after building the event
    after(:build) do |event|
      event.images.attach(
        io: File.open(Rails.root.join("spec/fixtures/files/test_image.jpg")),
        filename: "test_image.jpg",
        content_type: "image/jpeg"
      )
    end
  end
end
