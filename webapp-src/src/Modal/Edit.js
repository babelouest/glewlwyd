import React, { Component } from 'react';
import i18next from 'i18next';

class Edit extends Component {
  constructor(props) {
    super(props);

    this.state = {
      title: props.title,
      message: props.message,
      value: props.value,
      placeHolder: props.placeHolder,
      cb: props.callback
    }

    this.closeModal = this.closeModal.bind(this);
    this.changeValue = this.changeValue.bind(this);
  }

  componentWillReceiveProps(nextProps) {
    this.setState({
      title: nextProps.title,
      message: nextProps.message,
      value: nextProps.value,
      placeHolder: nextProps.placeHolder,
      cb: nextProps.callback
    });
  }

  closeModal(e, result) {
    if (this.state.cb) {
      this.state.cb(result, this.state.value);
    }
  }
  
  changeValue(e) {
    this.setState({value: e.target.value});
  }
  
	render() {
		return (
    <div className="modal fade" id="editModal" tabIndex="-1" role="dialog" aria-labelledby="editModalLabel" aria-hidden="true">
      <div className="modal-dialog modal-lg" role="document">
        <div className="modal-content">
          <div className="modal-header">
            <h5 className="modal-title" id="editModalLabel">{this.state.title}</h5>
            <button type="button" className="close" aria-label={i18next.t("modal.close")} onClick={(e) => this.closeModal(e, false)}>
              <span aria-hidden="true">&times;</span>
            </button>
          </div>
          <div className="modal-body">
            {this.state.message}
            <form className="needs-validation" noValidate>
              <div className="form-group">
                <input type="text" className="form-control" id="editModalInput" placeholder={this.state.placeHolder||""} value={this.state.value} onChange={(e) => this.changeValue(e)} />
              </div>
            </form>
          </div>
          <div className="modal-footer">
            <button type="button" className="btn btn-secondary" onClick={(e) => this.closeModal(e, false)}>{i18next.t("modal.close")}</button>
            <button type="button" className="btn btn-primary" onClick={(e) => this.closeModal(e, true)}>{i18next.t("modal.ok")}</button>
          </div>
        </div>
      </div>
    </div>
		);
	}
}

export default Edit;
