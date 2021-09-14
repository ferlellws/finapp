# frozen_string_literal: true

class User < ActiveRecord::Base
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable, :trackable and :omniauthable
  before_validation :set_uid
  devise :database_authenticatable,
         :confirmable,
         :registerable,
         :recoverable,
         :rememberable,
         :trackable,
         :validatable
        #  ,
        #  :omniauthable

  include DeviseTokenAuth::Concerns::User

  private

  def set_uid
    self.uid = self.email if self.uid.blank? and self.email.present?
  end
end
