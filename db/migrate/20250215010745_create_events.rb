class CreateEvents < ActiveRecord::Migration[7.2]
  def change
    create_table :events do |t|
      t.string :name
      t.string :description
      t.date :date
      t.text :image_urls,array: true, default: []
      t.text :video_urls,array: true, default: []
      t.references :user, foreign_key: true
      t.references :school, foreign_key: true
      t.timestamps
    end
  end
end
