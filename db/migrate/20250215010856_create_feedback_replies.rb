class CreateFeedbackReplies < ActiveRecord::Migration[7.2]
  def change
    create_table :feedback_replies do |t|
      t.text :reply
      t.references :user, foreign_key: true
      t.references :feedback, foreign_key: true
      t.timestamps
    end
  end
end
