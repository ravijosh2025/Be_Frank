class CreateFeedbacks < ActiveRecord::Migration[7.2]
  def change
    create_table :feedbacks do |t| 
      t.text :feedback
      t.references :user, foreign_key: true
      t.references :event, foreign_key: true
      t.timestamps
    end
  end
end
