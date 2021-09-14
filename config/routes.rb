require 'api_constraints'

Rails.application.routes.draw do
  namespace :api, defaults: { format: :json } do
    mount_devise_token_auth_for 'User', at: 'auth'
    
    scope module: :v1,
          constraints: ApiConstraints.new(version: 1, default: true) do
      resources :statuses
    end
  end

  # resources :statuses
  # For details on the DSL available within this file, see https://guides.rubyonrails.org/routing.html
end
