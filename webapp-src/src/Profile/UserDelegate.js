import React, { Component } from 'react';

import apiManager from '../lib/APIManager';

class UserDelegate extends Component {
  constructor(props) {
    super(props);
    
    this.state = {
      profile: props.profile
    };
    
  }
  
  componentWillReceiveProps(nextProps) {
    this.setState({
      profile: nextProps.profile
    });
  }
  
  render() {
    return (
      <div>
        <div className="row">
          <div className="col-md-12">
            <h4>{i18next.t("profile.hello-delegate", {name: (this.state.profile.name || this.state.profile.username)})}</h4>
          </div>
        </div>
      </div>
    );
  }
}

export default UserDelegate;
