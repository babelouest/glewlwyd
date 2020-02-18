import React, { Component } from 'react';
import i18next from 'i18next';

import apiManager from '../lib/APIManager';
import Notification from '../lib/Notification';

class App extends Component {
  constructor(props) {
    super(props);
    this.state = {
      config: props.config,
      stateDecoded: false
    };
    
    this.parseState();
  }
  
  Base64DecodeUrl(str){
    if (str.length % 4 == 2) {
      str += '==';
    } else if (str.length % 4 == 3) {
      str += '=';
    }
    return str.replace(/-/g, '+').replace(/_/g, '/');
  }
  
  parseState() {
    if (this.state.config.params.state) {
      var stateDecoded = false, type = false;
      try {
        var stateDecoded = JSON.parse(atob(this.Base64DecodeUrl(this.state.config.params.state)));
      } catch(e) {
        // TODO
        console.log(e);
      }
      if (stateDecoded && stateDecoded.type === "registration") {
        type = "registration";
        var data = {
          scheme_name: stateDecoded.module,
          scheme_type: "oauth2",
          username: stateDecoded.username,
          value: {
            action: "callback",
            provider: stateDecoded.provider,
            state: this.state.config.params.state,
            redirect_to: window.location.href
          }
        }
        $.ajax({
          method: "POST",
          url: stateDecoded.register_url + "/profile/scheme/register/",
          data: JSON.stringify(data),
          contentType: "application/json; charset=utf-8"
        })
        .then(() => {
          var url = stateDecoded.complete_url;
          if (url.indexOf('?') > -1) {
            url += '&';
          } else {
            url += '?';
          }
          url += "scheme_name=" + stateDecoded.module + "&provider=" + stateDecoded.provider;
          window.location.href = url;
        })
        .fail((err) => {
          if (err.status === 401) {
            $("#root").html('<div class="perfect-centering"><div class="alert alert-danger"><h3>Error authentication</h3></div><div class="row justify-content-md-center"><button type="button" class="btn btn-primary" id="buttonBack">Go to login page</button></div></div>');
          } else {
            $("#root").html('<div class="perfect-centering"><div class="alert alert-danger"><h3>Unknown error</h3></div><div class="row justify-content-md-center"><button type="button" class="btn btn-primary" id="buttonBack">Go to login page</button></div></div>');
          }
          $("#buttonBack").click(() => {
            var url = stateDecoded.complete_url;
            if (url.indexOf('?') > -1) {
              url += '&';
            } else {
              url += '?';
            }
            url += "scheme_name=" + stateDecoded.module + "&provider=" + stateDecoded.provider;
            window.location.href = url;
          });
        });
      } else if (stateDecoded.type === "authentication") {
        type = "authentication";
        var data = {
          scheme_name: stateDecoded.module,
          scheme_type: "oauth2",
          username: stateDecoded.username,
          value: {
            provider: stateDecoded.provider,
            state: this.state.config.params.state,
            redirect_to: window.location.href
          }
        }
        $.ajax({
          method: "POST",
          url: this.state.config.GlewlwydUrl + "/" + this.state.config.api_prefix + "/auth/",
          data: JSON.stringify(data),
          contentType: "application/json; charset=utf-8"
        })
        .then(() => {
          window.location.href = stateDecoded.callback_url;
        })
        .fail((err) => {
          if (err.status === 401) {
            $("#root").html('<div class="perfect-centering"><div class="alert alert-danger"><h3>Error authentication</h3></div><div class="row justify-content-md-center"><button type="button" class="btn btn-primary" id="buttonBack">Go to login page</button></div></div>');
          } else {
            $("#root").html('<div class="perfect-centering"><div class="alert alert-danger"><h3>Unknown error</h3></div><div class="row justify-content-md-center"><button type="button" class="btn btn-primary" id="buttonBack">Go to login page</button></div></div>');
          }
          $("#buttonBack").click(() => {
            window.location.href = stateDecoded.callback_url;
          });
        });
      } else {
        console.log(stateDecoded);
      }
    } else {
      console.log("no state");
    }
  }

	render() {
    if (this.state.config) {
      return ("");
    } else {
      return (
        <div aria-live="polite" aria-atomic="true" style={{position: "relative", minHeight: "200px"}}>
          <div className="card center" id="userCard" tabIndex="-1" role="dialog" style={{marginTop: 20 + 'px', marginBottom: 20 + 'px'}}>
            <div className="card-header">
              <h4>
                <span className="badge badge-danger">
                  {i18next.t("error-api-connect")}
                </span>
              </h4>
            </div>
          </div>
        </div>
      );
    }
	}
}

export default App;
